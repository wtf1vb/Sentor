// SentorWarp — standalone-ядро WARP/AmneziaWG для Sentor.
//
// Это вынесенный наружу код warp_wg.go из Go-версии: amneziawg-go работает
// не в процессе приложения (Rust не может встроить Go-библиотеку), а в
// отдельном процессе. Sentor запускает его вместо sing-box для серверов
// proto=warp и гасит закрытием stdin (graceful teardown) либо kill'ом.
//
// Использование: SentorWarp.exe <config.ini>
//   config.ini — текст wg-quick/AmneziaWG-конфига ([Interface]/[Peer] с
//   Jc/Jmin/Jmax/S1/S2/H1-H4 и приманками AWG 1.5 (I1-I5/J1-J3/ITime)).
//
// Протокол вывода (stdout читает Sentor и пишет в core_log.txt):
//   TUNNEL_UP          — туннель поднят (адаптер, адрес, DNS, маршруты)
//   FATAL: <текст>     — ошибка подъёма, процесс завершается с кодом 1
//   TUNNEL_DOWN        — graceful teardown по закрытию stdin, exit 0
// Прочие строки — диагностический лог (handshake-события и т.п.).
//
// wintun.dll ищется загрузчиком рядом с exe: Sentor кладёт SentorWarp.exe
// в tools\vpn\core, где уже лежит wintun.dll.
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
	"golang.org/x/sys/windows"
)

const warpIface = "sentor-warp"

// Фиксированный GUID wintun-адаптера WARP: адаптер
// переиспользуется между запусками, а не плодит «sentor-warp 2, 3».
var warpTunGUID = windows.GUID{
	Data1: 0xc1a9c5f3,
	Data2: 0x6e2b,
	Data3: 0x4d77,
	Data4: [8]byte{0x9a, 0x58, 0x3f, 0x2e, 0x1d, 0x4b, 0x7c, 0x90},
}

// warpConfig — распарсенный AmneziaWG/WireGuard-конфиг (порт warp_wg.go).
type warpConfig struct {
	privateKey string
	addresses  []string
	dns        []string
	mtu        int
	jc, jmin, jmax, s1, s2 int
	h1, h2, h3, h4        uint32
	hasAmnezia            bool
	// awgExtras — спец-поля AmneziaWG 1.5 (I1–I5, J1–J3, ITime) в исходном
	// виде "ключ=значение": генераторы junk-приманок для DPI, пробрасываются
	// в UAPI как есть
	awgExtras []string

	peerPublicKey    string
	peerPresharedKey string
	endpoint         string
	allowedIPs       []string
	keepalive        int
}

func parseWarpConfig(conf string) (*warpConfig, error) {
	c := &warpConfig{mtu: 1280}
	section := ""
	peerSections := 0
	sc := bufio.NewScanner(strings.NewReader(conf))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024) // I1-маска — длинная строка
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(strings.TrimSpace(strings.Trim(line, "[]")))
			if section == "peer" {
				peerSections++
				if peerSections > 1 {
					return nil, fmt.Errorf("конфиг с несколькими [Peer] не поддерживается — оставьте один пир")
				}
			}
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])
		switch section {
		case "interface":
			switch key {
			case "privatekey":
				c.privateKey = val
			case "address":
				for _, a := range strings.Split(val, ",") {
					if a = strings.TrimSpace(a); a != "" {
						c.addresses = append(c.addresses, a)
					}
				}
			case "dns":
				for _, d := range strings.Split(val, ",") {
					if d = strings.TrimSpace(d); d != "" {
						c.dns = append(c.dns, d)
					}
				}
			case "mtu":
				fmt.Sscanf(val, "%d", &c.mtu)
			case "jc":
				fmt.Sscanf(val, "%d", &c.jc)
				c.hasAmnezia = true
			case "jmin":
				fmt.Sscanf(val, "%d", &c.jmin)
				c.hasAmnezia = true
			case "jmax":
				fmt.Sscanf(val, "%d", &c.jmax)
				c.hasAmnezia = true
			case "s1":
				fmt.Sscanf(val, "%d", &c.s1)
				c.hasAmnezia = true
			case "s2":
				fmt.Sscanf(val, "%d", &c.s2)
				c.hasAmnezia = true
			case "h1":
				fmt.Sscanf(val, "%d", &c.h1)
				c.hasAmnezia = true
			case "h2":
				fmt.Sscanf(val, "%d", &c.h2)
				c.hasAmnezia = true
			case "h3":
				fmt.Sscanf(val, "%d", &c.h3)
				c.hasAmnezia = true
			case "h4":
				fmt.Sscanf(val, "%d", &c.h4)
				c.hasAmnezia = true
			default:
				switch key {
				case "i1", "i2", "i3", "i4", "i5", "j1", "j2", "j3", "itime":
					if val != "" {
						c.awgExtras = append(c.awgExtras, key+"="+val)
						c.hasAmnezia = true
					}
				}
			}
		case "peer":
			switch key {
			case "publickey":
				c.peerPublicKey = val
			case "presharedkey":
				c.peerPresharedKey = val
			case "endpoint":
				c.endpoint = val
			case "allowedips":
				for _, cidr := range strings.Split(val, ",") {
					if cidr = strings.TrimSpace(cidr); cidr != "" {
						// голый IP (без префикса) UAPI отвергает — нормализуем сами
						if net.ParseIP(cidr) != nil {
							if strings.Contains(cidr, ":") {
								cidr += "/128"
							} else {
								cidr += "/32"
							}
						}
						c.allowedIPs = append(c.allowedIPs, cidr)
					}
				}
			case "persistentkeepalive":
				fmt.Sscanf(val, "%d", &c.keepalive)
			}
		}
	}
	if c.privateKey == "" {
		return nil, fmt.Errorf("в конфиге нет PrivateKey")
	}
	if c.peerPublicKey == "" {
		return nil, fmt.Errorf("в конфиге нет PublicKey пира")
	}
	if len(c.addresses) == 0 {
		return nil, fmt.Errorf("в конфиге нет Address")
	}
	if c.endpoint == "" {
		return nil, fmt.Errorf("в конфиге нет Endpoint — туннель без него не поднимется")
	}
	// IP-endpoint без порта: StdNetBind.ParseEndpoint требует host:port
	if ip := net.ParseIP(strings.Trim(c.endpoint, "[]")); ip != nil {
		c.endpoint = net.JoinHostPort(strings.Trim(c.endpoint, "[]"), "2408")
	}
	if c.mtu <= 0 || c.mtu > 1600 {
		c.mtu = 1280
	}
	return c, nil
}

func (c *warpConfig) hostPort() (string, int) {
	host, portStr, err := net.SplitHostPort(c.endpoint)
	if err != nil {
		host = strings.Trim(c.endpoint, "[]")
		portStr = "2408"
	}
	port, _ := strconv.Atoi(portStr)
	if port <= 0 || port > 65535 {
		port = 2408
	}
	return host, port
}

// uapi — конфиг в формате UAPI set-операции (порт warp_wg.go).
func (c *warpConfig) uapi() string {
	var b strings.Builder
	if c.hasAmnezia {
		if c.jc > 0 {
			b.WriteString(fmt.Sprintf("jc=%d\n", c.jc))
		}
		if c.jmin > 0 {
			b.WriteString(fmt.Sprintf("jmin=%d\n", c.jmin))
		}
		if c.jmax > 0 {
			b.WriteString(fmt.Sprintf("jmax=%d\n", c.jmax))
		}
		if c.s1 > 0 {
			b.WriteString(fmt.Sprintf("s1=%d\n", c.s1))
		}
		if c.s2 > 0 {
			b.WriteString(fmt.Sprintf("s2=%d\n", c.s2))
		}
		if c.h1 > 0 {
			b.WriteString(fmt.Sprintf("h1=%d\n", c.h1))
		}
		if c.h2 > 0 {
			b.WriteString(fmt.Sprintf("h2=%d\n", c.h2))
		}
		if c.h3 > 0 {
			b.WriteString(fmt.Sprintf("h3=%d\n", c.h3))
		}
		if c.h4 > 0 {
			b.WriteString(fmt.Sprintf("h4=%d\n", c.h4))
		}
	}
	for _, extra := range c.awgExtras {
		b.WriteString(extra + "\n")
	}
	b.WriteString("private_key=" + keyToHex(c.privateKey) + "\n")
	b.WriteString("public_key=" + keyToHex(c.peerPublicKey) + "\n")
	if c.peerPresharedKey != "" {
		b.WriteString("preshared_key=" + keyToHex(c.peerPresharedKey) + "\n")
	}
	if c.endpoint != "" {
		b.WriteString("endpoint=" + c.endpoint + "\n")
	}
	for _, cidr := range c.allowedIPs {
		b.WriteString("allowed_ip=" + cidr + "\n")
	}
	if c.keepalive > 0 {
		b.WriteString("persistent_keepalive_interval=" + strconv.Itoa(c.keepalive) + "\n")
	}
	b.WriteString("\n")
	return b.String()
}

func keyToHex(b64 string) string {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return b64
	}
	return hex.EncodeToString(raw)
}

// cmdTimeout — netsh/route на свежесозданном интерфейсе может висеть десятки
// секунд (порт pwdtt_wg.go).
const cmdTimeout = 30 * time.Second

func runCmd(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("%s %v: не дождались (%s)", name, args, ctx.Err())
		}
		return fmt.Errorf("%s %v: %w — %s", name, args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func parseCIDR(cidr string) (ip, mask string, err error) {
	parts := strings.SplitN(cidr, "/", 2)
	if len(parts) != 2 {
		return cidr, "255.255.255.255", nil
	}
	ip = parts[0]
	var prefix int
	if _, e := fmt.Sscanf(parts[1], "%d", &prefix); e != nil || prefix < 0 || prefix > 32 {
		return "", "", fmt.Errorf("invalid prefix %q", parts[1])
	}
	var m uint32
	if prefix > 0 {
		m = ^uint32(0) << (32 - prefix)
	}
	mask = fmt.Sprintf("%d.%d.%d.%d", m>>24, (m>>16)&0xff, (m>>8)&0xff, m&0xff)
	return ip, mask, nil
}

// routeLines — строки route print <filter> с совпадающим первым полем.
func routeLines(filter string) string {
	cmd := exec.Command("cmd", "/c", "route", "print", filter)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	raw, err := cmd.Output()
	if err != nil {
		return ""
	}
	var rows []string
	for _, ln := range strings.Split(string(raw), "\n") {
		f := strings.Fields(ln)
		if len(f) >= 5 && (f[0] == filter || (filter == "0.0.0.0" && f[0] == "0.0.0.0" && f[1] == "0.0.0.0")) {
			rows = append(rows, strings.Join(f, " "))
		}
	}
	return strings.Join(rows, " | ")
}

// defaultRoute — текущий дефолт-маршрут: шлюз и адрес физического интерфейса.
func defaultRoute() (gw, ifIP string) {
	cmd := exec.Command("cmd", "/c", "route", "print", "0.0.0.0")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, err := cmd.Output()
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) >= 5 && f[0] == "0.0.0.0" && f[1] == "0.0.0.0" && net.ParseIP(f[2]) != nil {
			return f[2], f[3]
		}
	}
	return "", ""
}

// interfaceIndexByAddr — индекс интерфейса Windows, на котором живёт этот IP.
func interfaceIndexByAddr(ipStr string) int {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0
	}
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.Equal(ip) {
				return ifc.Index
			}
		}
	}
	return 0
}

// cleanupStale — хвосты жёстко убитой прошлой сессии: дефолт-маршруты через
// адаптер sentor-warp и задранный метрикой физический дефолт (порт
// warpCleanupStale). Вызывается при старте перед Apply.
func cleanupStale() {
	for _, cidr := range []string{"0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1"} {
		_ = runCmd("netsh", "interface", "ip", "delete", "route", "prefix="+cidr, "interface="+warpIface)
	}
	for _, cidr := range []string{"::/0", "::/1", "8000::/1"} {
		_ = runCmd("netsh", "interface", "ipv6", "delete", "route", "prefix="+cidr, "interface="+warpIface)
	}
	_ = runCmd("netsh", "interface", "ip", "set", "dns", "name="+warpIface, "source=dhcp")
	// осиротевший адаптер после TerminateProcess: CreateAdapter с тем же GUID
	// упадёт «already exists» — сносим PnP-устройство best-effort
	deleteStaleAdapter()
	for _, row := range strings.Split(routeLines("0.0.0.0"), " | ") {
		f := strings.Fields(row)
		if len(f) >= 5 && f[4] == "9999" && net.ParseIP(f[2]) != nil {
			_ = runCmd("route", "change", "0.0.0.0", "mask", "0.0.0.0", f[2], "metric", "35")
			break
		}
	}
}

// deleteStaleAdapter — убрать осиротевший wintun-адаптер (после жёсткого
// килла процесса адаптер живёт в системе и блокирует создание с тем же
// GUID/именем). wintun-обёртка в amneziawg-go не экспортирует DeleteAdapter,
// поэтому зовём WintunDeleteAdapter из wintun.dll напрямую (dll лежит рядом
// с хелпером в tools\vpn\core).
func deleteStaleAdapter() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	dllPath := filepath.Join(filepath.Dir(exe), "wintun.dll")
	if _, serr := os.Stat(dllPath); serr != nil {
		return
	}
	dll := windows.NewLazyDLL(dllPath)
	open := dll.NewProc("WintunOpenAdapter")
	del := dll.NewProc("WintunDeleteAdapter")
	closeP := dll.NewProc("WintunCloseAdapter")
	name, nerr := windows.UTF16PtrFromString(warpIface)
	if nerr != nil {
		return
	}
	h, _, _ := open.Call(uintptr(unsafe.Pointer(name)))
	if h == 0 {
		return // адаптера нет — нечего удалять
	}
	var reboot int32
	del.Call(h, 0, uintptr(unsafe.Pointer(&reboot)))
	closeP.Call(h)
}

// warpWG — активная сессия туннеля (порт warp_wg.go без межсессионных эпох:
// у хелпера одна сессия на процесс).
type warpWG struct {
	activeRoutes        []string
	activeExcludeRoutes []string
	activeDevice        *device.Device
	activeTun           tun.Device
	bind                conn.Bind
	activeDNS           []string
	dnsDone             chan struct{}
	dnsStop             chan struct{}
	stateMu             sync.Mutex
}

func (w *warpWG) teardown() {
	w.stateMu.Lock()
	defer w.stateMu.Unlock()
	w.teardownLocked()
}

func (w *warpWG) teardownLocked() {
	for _, cidr := range w.activeRoutes {
		if strings.Contains(cidr, ":") {
			_ = runCmd("netsh", "interface", "ipv6", "delete", "route", cidr, "interface="+warpIface)
		} else {
			_ = runCmd("netsh", "interface", "ip", "delete", "route", cidr, warpIface)
		}
	}
	w.activeRoutes = nil
	for _, cidr := range w.activeExcludeRoutes {
		if ip, _, err := parseCIDR(cidr); err == nil && ip != "" {
			_ = runCmd("route", "delete", ip)
		}
	}
	w.activeExcludeRoutes = nil
	if w.dnsStop != nil {
		close(w.dnsStop)
		w.dnsStop = nil
	}
	if w.dnsDone != nil {
		select {
		case <-w.dnsDone:
		case <-time.After(8 * time.Second):
		}
		w.dnsDone = nil
	}
	if len(w.activeDNS) > 0 {
		_ = runCmd("netsh", "interface", "ip", "set", "dns", "name="+warpIface, "source=dhcp")
	}
	w.activeDNS = nil
	if w.activeDevice != nil {
		w.activeDevice.Close()
		w.activeDevice = nil
	}
	if w.activeTun != nil {
		w.activeTun.Close()
		w.activeTun = nil
	}
}

// apply — поднять туннель: wintun → amneziawg device → адрес/DNS → маршруты
// (порт warp_wg.go::Apply).
func (w *warpWG) apply(conf string, logf func(string)) (applyErr error) {
	w.stateMu.Lock()
	defer w.stateMu.Unlock()
	cleanupStale()
	w.teardownLocked()
	defer func() {
		if applyErr != nil {
			logf("Откат после ошибки: " + applyErr.Error())
			w.teardownLocked()
		}
	}()

	cfg, err := parseWarpConfig(conf)
	if err != nil {
		return err
	}
	// UAPI amneziawg понимает endpoint только IP:port — hostname резолвим заранее
	if eh, _ := cfg.hostPort(); net.ParseIP(eh) == nil {
		_, port := cfg.hostPort()
		ips, lerr := net.LookupIP(eh)
		if lerr != nil || len(ips) == 0 {
			logf(fmt.Sprintf("Не смог резолвить endpoint %s: %v — IpcSet может упасть", eh, lerr))
		} else {
			pick := ips[0]
			for _, ip := range ips {
				if ip.To4() != nil {
					pick = ip
					break
				}
			}
			logf(fmt.Sprintf("Endpoint %s → %s", eh, pick.String()))
			cfg.endpoint = net.JoinHostPort(pick.String(), strconv.Itoa(port))
		}
	}

	logf(fmt.Sprintf("Создание TUN-интерфейса %q (mtu=%d, amnezia=%v)", warpIface, cfg.mtu, cfg.hasAmnezia))
	tunDev, err := tun.CreateTUNWithRequestedGUID(warpIface, &warpTunGUID, cfg.mtu)
	if err != nil {
		if strings.Contains(err.Error(), "cannot find the file") {
			return fmt.Errorf("create TUN: %w — слой wintun-драйвера в сломанном состоянии, перезагрузи ПК и попробуй снова", err)
		}
		return fmt.Errorf("create TUN: %w", err)
	}
	w.activeTun = tunDev

	logger := &device.Logger{
		// Verbose нужен в логе: там видно «handshake initiation/response» —
		// без этого блокировка endpoint'а выглядит как молчаливый таймаут.
		// Кроме спама «lined up with another msg type» при дефолтных H1-H4.
		Verbosef: func(format string, args ...interface{}) {
			msg := fmt.Sprintf(format, args...)
			if strings.Contains(msg, "lined up with another msg type") {
				return
			}
			logf(msg)
		},
		Errorf: func(format string, args ...interface{}) { logf(fmt.Sprintf(format, args...)) },
	}
	bind := conn.NewDefaultBind()
	dev := device.NewDevice(tunDev, bind, logger)
	w.activeDevice = dev
	w.bind = bind

	logf("Применение AmneziaWG конфига (uapi)")
	if err := dev.IpcSetOperation(strings.NewReader(cfg.uapi())); err != nil {
		return fmt.Errorf("IpcSet: %w", err)
	}
	if err := dev.Up(); err != nil {
		return fmt.Errorf("device up: %w", err)
	}
	logf("AmneziaWG устройство поднято")

	// Адрес интерфейса: v4 — через ipv4 netsh, v6 — best-effort в фоне.
	v4, v6 := "", ""
	for _, a := range cfg.addresses {
		if strings.Contains(a, ":") {
			if v6 == "" {
				v6 = a
			}
		} else if v4 == "" {
			v4 = a
		}
	}
	if v4 != "" {
		if host, mask, perr := parseCIDR(v4); perr == nil && host != "" {
			if err := runCmd("netsh", "interface", "ip", "set", "address",
				"name="+warpIface, "source=static", host, mask); err != nil {
				logf("netsh set address: " + err.Error())
			}
		} else {
			_ = runCmd("netsh", "interface", "ip", "set", "address",
				"name="+warpIface, "source=static", v4, "none")
		}
	}
	// Низкая метрика интерфейса, чтобы маршруты через туннель били физические.
	_ = runCmd("netsh", "interface", "ip", "set", "interface",
		"interface="+warpIface, "metric=1")

	// Реальный MTU на адаптере: wintun создаёт NIC с гигантским MTU, и Windows
	// гонит в туннель огромные кадры — WinRing-bind отбрасывает всё, что
	// больше ~2 КБ (io.ErrShortBuffer).
	logf(fmt.Sprintf("MTU адаптера %s → %d", warpIface, cfg.mtu))
	_ = runCmd("netsh", "interface", "ipv4", "set", "subinterface",
		warpIface, "mtu="+strconv.Itoa(cfg.mtu), "store=active")
	_ = runCmd("netsh", "interface", "ipv6", "set", "subinterface",
		warpIface, "mtu="+strconv.Itoa(cfg.mtu), "store=active")

	// DNS и v6-адрес — в фоне: netsh на свежесозданном интерфейсе может висеть.
	dnsDone := make(chan struct{})
	dnsStop := make(chan struct{})
	w.dnsDone = dnsDone
	w.dnsStop = dnsStop
	go func() {
		defer close(dnsDone)
		stopped := func() bool {
			select {
			case <-dnsStop:
				return true
			default:
				return false
			}
		}
		if v6 != "" {
			if stopped() {
				return
			}
			if err := runCmd("netsh", "interface", "ipv6", "set", "address",
				"interface="+warpIface, "addr="+strings.SplitN(v6, "/", 2)[0]); err != nil {
				logf("ipv6 set address: " + err.Error())
			}
		}
		v4Set := false
		v4Count := 0
		for _, d := range cfg.dns {
			if strings.Contains(d, ":") {
				continue
			}
			if stopped() {
				return
			}
			var err error
			if !v4Set {
				err = runCmd("netsh", "interface", "ip", "set", "dns", "name="+warpIface, "static", d)
				v4Set = true
			} else {
				err = runCmd("netsh", "interface", "ip", "add", "dns", "name="+warpIface, d)
			}
			if err != nil {
				logf("netsh dns " + d + ": " + err.Error())
				continue
			}
			v4Count++
		}
		if v4Set {
			logf("DNS интерфейса настроен (" + strconv.Itoa(v4Count) + " серверов, v6 пропущены)")
		}
	}()
	w.activeDNS = append([]string(nil), cfg.dns...)

	// Привязываем UDP-сокет WG к физическому интерфейсу (защита от петли —
	// модель официального клиента wireguard-windows).
	gw, gwIfIP := defaultRoute()
	logf("Default gateway: " + gw)
	if idx := interfaceIndexByAddr(gwIfIP); idx > 0 {
		if bi, ok := bind.(conn.BindSocketToInterface); ok {
			if err := bi.BindSocketToInterface4(uint32(idx), false); err != nil {
				logf(fmt.Sprintf("Привязка v4-сокета к интерфейсу %d не удалась: %v", idx, err))
			}
			if err := bi.BindSocketToInterface6(uint32(idx), false); err != nil {
				logf(fmt.Sprintf("Привязка v6-сокета к интерфейсу %d не удалась (не критично): %v", idx, err))
			}
			logf(fmt.Sprintf("UDP-сокет привязан к физическому интерфейсу (ifIndex %d)", idx))
		}
	} else {
		logf("Не нашёл физический интерфейс по адресу " + gwIfIP + " — полагаюсь на исключающий маршрут")
	}

	// Исключающие маршруты: /32 до endpoint через физический шлюз.
	var excludes []string
	if gw != "" {
		eh, _ := cfg.hostPort()
		var endpoints []net.IP
		if eh != "" {
			if ip := net.ParseIP(eh); ip != nil {
				endpoints = append(endpoints, ip)
			} else if ips, err := net.LookupIP(eh); err == nil {
				endpoints = append(endpoints, ips...)
			} else {
				logf(fmt.Sprintf("Не смог резолвить endpoint %s: %v — возможна петля маршрутизации", eh, err))
			}
		}
		for _, ip := range endpoints {
			if ip.To4() == nil {
				continue
			}
			ipS, mask, _ := parseCIDR(ip.String() + "/32")
			addErr := runCmd("route", "add", ipS, "mask", mask, gw, "metric", "1")
			if addErr != nil {
				// маршрут мог остаться от жёстко убитой сессии
				_ = runCmd("route", "delete", ipS)
				addErr = runCmd("route", "add", ipS, "mask", mask, gw, "metric", "1")
			}
			if addErr != nil {
				logf(fmt.Sprintf("route add %s failed: %v", ip.String(), addErr))
				continue
			}
			excludes = append(excludes, ip.String()+"/32")
		}
		if len(excludes) > 0 {
			logf("Endpoint исключён из туннеля: " + strings.Join(excludes, ", "))
		}
	}
	w.activeExcludeRoutes = excludes

	// Маршруты туннеля: AllowedIPs (полный дефолт 0.0.0.0/0 и ::/0) через TUN.
	var routes []string
	var failedRoutes []string
	seenRoute := map[string]bool{}
	for _, cidr := range cfg.allowedIPs {
		if seenRoute[cidr] {
			continue
		}
		seenRoute[cidr] = true
		verb := []string{"netsh", "interface", "ip", "add", "route"}
		if strings.Contains(cidr, ":") {
			verb = []string{"netsh", "interface", "ipv6", "add", "route"}
		}
		cmd := append(verb, "prefix="+cidr, "interface="+warpIface, "metric=0", "store=active")
		err := runCmd(cmd[0], cmd[1:]...)
		if err != nil {
			// маршрут мог остаться от жёстко убитой сессии — снесём и повторим
			delVerb := []string{"netsh", "interface", "ip", "delete", "route"}
			if strings.Contains(cidr, ":") {
				delVerb = []string{"netsh", "interface", "ipv6", "delete", "route"}
			}
			_ = runCmd(delVerb[0], append(delVerb[1:], "prefix="+cidr, "interface="+warpIface)...)
			err = runCmd(cmd[0], cmd[1:]...)
		}
		if err != nil {
			logf(fmt.Sprintf("netsh add route %s failed: %v", cidr, err))
			failedRoutes = append(failedRoutes, cidr)
		} else {
			routes = append(routes, cidr)
		}
	}
	w.activeRoutes = routes
	logf(fmt.Sprintf("Туннель %s поднят, маршрутов: %d, AllowedIPs: %v", warpIface, len(routes), cfg.allowedIPs))
	if len(failedRoutes) > 0 {
		// fail-open недопустим: трафик пошёл бы МИМО туннеля при «Подключено».
		return fmt.Errorf("не удалось добавить маршруты (%s) — туннель не включён, откатываю всё созданное", strings.Join(failedRoutes, ", "))
	}
	for _, f := range []string{"0.0.0.0", endpointIPString(cfg)} {
		if f == "" {
			continue
		}
		if rows := routeLines(f); rows != "" {
			logf("route print " + f + " → " + rows)
		}
	}
	return nil
}

// endpointIPString — IP endpoint'а конфига (если это литерал).
func endpointIPString(cfg *warpConfig) string {
	eh, _ := cfg.hostPort()
	if net.ParseIP(eh) != nil {
		return eh
	}
	return ""
}

// stripI1 — убрать I1-I5 приманки из текста конфига. I1-маски статические
// (warp_i1_mask.go) и DPI со временем их выучивает: на сетях, где маска
// «сгорела», handshake с ней молчит, а без неё (только Jc-junk) проходит.
func stripI1(conf string) string {
	var out []string
	for _, ln := range strings.Split(conf, "\n") {
		k := strings.ToLower(strings.TrimSpace(ln))
		if strings.HasPrefix(k, "i1 ") || strings.HasPrefix(k, "i1=") ||
			strings.HasPrefix(k, "i2 ") || strings.HasPrefix(k, "i2=") ||
			strings.HasPrefix(k, "i3 ") || strings.HasPrefix(k, "i3=") ||
			strings.HasPrefix(k, "i4 ") || strings.HasPrefix(k, "i4=") ||
			strings.HasPrefix(k, "i5 ") || strings.HasPrefix(k, "i5=") {
			continue
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}

// Список портов для перебора: порт конфига идёт первым, затем классика
// Cloudflare WARP. «Альтернативные» порты 854-8886 из warp-awg-gen устарели —
// Cloudflare на них не отвечает (проверено на живой сети 2026-11: IP жив по
// TCP, handshake на 945 молчит, на 1701 проходит).
var rotateShortlist = []int{1701, 500, 4500, 2408}

// i1Masks — пара QUIC-масок, та же, что вшита в генератор Sentor
// (warp-config-ru, MIT). Хелпер подставляет их по очереди: в старом конфиге
// маска могла «сгореть» (DPI выучил её), а без маски DPI режет handshake на
// всех портах.
var i1Masks = []string{
	"I1 = <b 0xc10000000114367096bb0fb3f58f3a3fb8aaacd61d63a1c8a40e14f7374b8a62dccba6431716c3abf6f5afbcfb39bd008000047c32e268567c652e6f4db58bff759bc8c5aaca183b87cb4d22938fe7d8dca22a679a79e4d9ee62e4bbb3a380dd78d4e8e48f26b38a1d42d76b371a5a9a0444827a69d1ab5872a85749f65a4104e931740b4dc1e2dd77733fc7fac4f93011cd622f2bb47e85f71992e2d585f8dc765a7a12ddeb879746a267393ad023d267c4bd79f258703e27345155268bd3cc0506ebd72e2e3c6b5b0f005299cd94b67ddabe30389c4f9b5c2d512dcc298c14f14e9b7f931e1dc397926c31fbb7cebfc668349c218672501031ecce151d4cb03c4c660b6c6fe7754e75446cd7de09a8c81030c5f6fb377203f551864f3d83e27de7b86499736cbbb549b2f37f436db1cae0a4ea39930f0534aacdd1e3534bc87877e2afabe959ced261f228d6362e6fd277c88c312d966c8b9f67e4a92e757773db0b0862fb8108d1d8fa262a40a1b4171961f0704c8ba314da2482ac8ed9bd28d4b50f7432d89fd800c25a50c5e2f5c0710544fef5273401116aa0572366d8e49ad758fcb29e6a92912e644dbe227c247cb3417eabfab2db16796b2fba420de3b1dc94e8361f1f324a331ddaf1e626553138860757fd0bf687566108b77b70fb9f8f8962eca599c4a70ed373666961a8cb506b96756d9e28b94122b20f16b54f118c0e603ce0b831efea614ad836df6cf9affbdd09596412547496967da758cec9080295d853b0861670b71d9abde0d562b1a6de82782a5b0c14d297f27283a895abc889a5f6703f0e6eb95f67b2da45f150d0d8ab805612d570c2d5cb6997ac3a7756226c2f5c8982ffbd480c5004b0660a3c9468945efde90864019a2b519458724b55d766e16b0da25c0557c01f3c11ddeb024b62e303640e17fdd57dedb3aeb4a2c1b7c93059f9c1d7118d77caac1cd0f6556e46cbc991c1bb16970273dea833d01e5090d061a0c6d25af2415cd2878af97f6d0e7f1f936247b394ecb9bd484da6be936dee9b0b92dc90101a1b4295e97a9772f2263eb09431995aa173df4ca2abd687d87706f0f93eaa5e13cbe3b574fa3cfe94502ace25265778da6960d561381769c24e0cbd7aac73c16f95ae74ff7ec38124f7c722b9cb151d4b6841343f29be8f35145e1b27021056820fed77003df8554b4155716c8cf6049ef5e318481460a8ce3be7c7bfac695255be84dc491c19e9dedc449dd3471728cd2a3ee51324ccb3eef121e3e08f8e18f0006ea8957371d9f2f739f0b89e4db11e5c6430ada61572e589519fbad4498b460ce6e4407fc2d8f2dd4293a50a0cb8fcaaf35cd9a8cc097e3603fbfa08d9036f52b3e7fcce11b83ad28a4ac12dba0395a0cc871cefd1a2856fffb3f28d82ce35cf80579974778bab13d9b3578d8c75a2d196087a2cd439aff2bb33f2db24ac175fff4ed91d36a4cdbfaf3f83074f03894ea40f17034629890da3efdbb41141b38368ab532209b69f057ddc559c19bc8ae62bf3fd564c9a35d9a83d14a95834a92bae6d9a29ae5e8ece07910d16433e4c6230c9bd7d68b47de0de9843988af6dc88b5301820443bd4d0537778bf6b4c1dd067fcf14b81015f2a67c7f2a28f9cb7e0684d3cb4b1c24d9b343122a086611b489532f1c3a26779da1706c6759d96d8ab>",
	"I1 = <b 0xce000000010897a297ecc34cd6dd000044d0ec2e2e1ea2991f467ace4222129b5a098823784694b4897b9986ae0b7280135fa85e196d9ad980b150122129ce2a9379531b0fd3e871ca5fdb883c369832f730e272d7b8b74f393f9f0fa43f11e510ecb2219a52984410c204cf875585340c62238e14ad04dff382f2c200e0ee22fe743b9c6b8b043121c5710ec289f471c91ee414fca8b8be8419ae8ce7ffc53837f6ade262891895f3f4cecd31bc93ac5599e18e4f01b472362b8056c3172b513051f8322d1062997ef4a383b01706598d08d48c221d30e74c7ce000cdad36b706b1bf9b0607c32ec4b3203a4ee21ab64df336212b9758280803fcab14933b0e7ee1e04a7becce3e2633f4852585c567894a5f9efe9706a151b615856647e8b7dba69ab357b3982f554549bef9256111b2d67afde0b496f16962d4957ff654232aa9e845b61463908309cfd9de0a6abf5f425f577d7e5f6440652aa8da5f73588e82e9470f3b21b27b28c649506ae1a7f5f15b876f56abc4615f49911549b9bb39dd804fde182bd2dcec0c33bad9b138ca07d4a4a1650a2c2686acea05727e2a78962a840ae428f55627516e73c83dd8893b02358e81b524b4d99fda6df52b3a8d7a5291326e7ac9d773c5b43b8444554ef5aea104a738ed650aa979674bbed38da58ac29d87c29d387d80b526065baeb073ce65f075ccb56e47533aef357dceaa8293a523c5f6f790be90e4731123d3c6152a70576e90b4ab5bc5ead01576c68ab633ff7d36dcde2a0b2c68897e1acfc4d6483aaaeb635dd63c96b2b6a7a2bfe042f6aed82e5363aa850aace12ee3b1a93f30d8ab9537df483152a5527faca21efc9981b304f11fc95336f5b9637b174c5a0659e2b22e159a9fed4b8e93047371175b1d6d9cc8ab745f3b2281537d1c75fb9451871864efa5d184c38c185fd203de206751b92620f7c369e031d2041e152040920ac2c5ab5340bfc9d0561176abf10a147287ea90758575ac6a9f5ac9f390d0d5b23ee12af583383d994e22c0cf42383834bcd3ada1b3825a0664d8f3fb678261d57601ddf94a8a68a7c273a18c08aa99c7ad8c6c42eab67718843597ec9930457359dfdfbce024afc2dcf9348579a57d8d3490b2fa99f278f1c37d87dad9b221acd575192ffae1784f8e60ec7cee4068b6b988f0433d96d6a1b1865f4e155e9fe020279f434f3bf1bd117b717b92f6cd1cc9bea7d45978bcc3f24bda631a36910110a6ec06da35f8966c9279d130347594f13e9e07514fa370754d1424c0a1545c5070ef9fb2acd14233e8a50bfc5978b5bdf8bc1714731f798d21e2004117c61f2989dd44f0cf027b27d4019e81ed4b5c31db347c4a3a4d85048d7093cf16753d7b0d15e078f5c7a5205dc2f87e330a1f716738dce1c6180e9d02869b5546f1c4d2748f8c90d9693cba4e0079297d22fd61402dea32ff0eb69ebd65a5d0b687d87e3a8b2c42b648aa723c7c7daf37abcc4bb85caea2ee8f55bec20e913b3324ab8f5c3304f820d42ad1b9f2ffc1a3af9927136b4419e1e579ab4c2ae3c776d293d397d575df181e6cae0a4ada5d67ecea171cca3288d57c7bbdaee3befe745fb7d634f70386d873b90c4d6c6596bb65af68f9e5121e67ebf0d89d3c909ceedfb32ce9575a7758ff080724e1ab5d5f43074ecb53a479af21ed03d7b6899c36631c0166f9d47e5e1d4528a5d3d3f744029c4b1c190cbfbad06f5f83f7ad0429fa9a2719c56ffe3783460e166de2d8>",
}

// replaceI1 — заменить строку I1 в конфиге на другую маску
func replaceI1(conf, mask string) string {
	lines := strings.Split(conf, "\n")
	for i, ln := range lines {
		k := strings.ToLower(strings.TrimSpace(ln))
		if strings.HasPrefix(k, "i1 ") || strings.HasPrefix(k, "i1=") {
			lines[i] = mask
		}
	}
	return strings.Join(lines, "\n")
}

// rotatePorts — кандидаты портов: порт из конфига + шортлист без дублей,
// не больше 10 — худший случай ограничен несколькими минутами.
func rotatePorts(cfgPort int) []int {
	out := []int{cfgPort}
	for _, p := range rotateShortlist {
		if p == cfgPort {
			continue
		}
		dup := false
		for _, q := range out {
			if q == p {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, p)
		}
		if len(out) >= 10 {
			break
		}
	}
	return out
}

// replaceEndpointPort — подменить порт в строке Endpoint конфига (host тот же)
func replaceEndpointPort(conf, host string, oldPort, newPort int) string {
	if oldPort == newPort {
		return conf
	}
	oldEp := fmt.Sprintf("%s:%d", host, oldPort)
	newEp := fmt.Sprintf("%s:%d", host, newPort)
	lines := strings.Split(conf, "\n")
	for i, ln := range lines {
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(ln)), "endpoint") {
			continue
		}
		if strings.Contains(ln, oldEp) {
			lines[i] = strings.Replace(ln, oldEp, newEp, 1)
		} else if strings.Contains(strings.TrimSpace(ln), "[") {
			lines[i] = fmt.Sprintf("Endpoint = [%s]:%d", host, newPort)
		} else {
			lines[i] = fmt.Sprintf("Endpoint = %s:%d", host, newPort)
		}
	}
	return strings.Join(lines, "\n")
}

// waitHandshake — ждать появления handshake response до d
func waitHandshake(hsMu *sync.Mutex, seen *bool, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		hsMu.Lock()
		s := *seen
		hsMu.Unlock()
		if s {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func main() {
	// детект handshake: Verbosef-лог amneziawg-go содержит
	// «Received handshake response» при живом туннеле
	var hsMu sync.Mutex
	handshakeSeen := false
	logf := func(msg string) {
		hsMu.Lock()
		if strings.Contains(msg, "handshake response") {
			handshakeSeen = true
		}
		hsMu.Unlock()
		fmt.Println(msg)
	}
	if len(os.Args) < 2 {
		fmt.Println("FATAL: usage: SentorWarp.exe <config.ini>")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println("FATAL: " + err.Error())
		os.Exit(1)
	}
	// BOM (Notepad/PowerShell любят UTF-8/UTF-16 с BOM) ломает разбор секций —
	// снимаем, как warpDecodeConfFile
	conf := strings.TrimPrefix(string(data), "\ufeff")

	// Живость WARP-порта нельзя проверить «сбоку» (UDP, нужен полный
	// WG-handshake), а DPI операторов режет классические порты и часть
	// альтернатив — на одной сети жив 1701, на другой 945. Поэтому конфиг с
	// непроверенным портом — лотерея. Перебираем порты из шортлиста: для
	// каждого две попытки (с I1-приманками и без — маска могла «сгореть»),
	// пока не придёт handshake response. Пришёл — подключено; перебор исчерпан
	// — FATAL (Sentor покажет ошибку вместо «подключено без интернета»).
	cfg, perr := parseWarpConfig(conf)
	if perr != nil {
		fmt.Println("FATAL: " + perr.Error())
		os.Exit(1)
	}
	host, port := cfg.hostPort()
	ports := rotatePorts(port)
	hasI1 := false
	for _, e := range cfg.awgExtras {
		if strings.HasPrefix(e, "i1 ") || strings.HasPrefix(e, "i1=") ||
			strings.HasPrefix(e, "i2 ") || strings.HasPrefix(e, "i2=") ||
			strings.HasPrefix(e, "i3 ") || strings.HasPrefix(e, "i3=") ||
			strings.HasPrefix(e, "i4 ") || strings.HasPrefix(e, "i4=") ||
			strings.HasPrefix(e, "i5 ") || strings.HasPrefix(e, "i5=") {
			hasI1 = true
			break
		}
	}

	w := &warpWG{}
	success := false
attemptLoop:
	for _, p := range ports {
		tryConf := replaceEndpointPort(conf, host, port, p)
		variants := []string{tryConf}
		if hasI1 {
			for _, m := range i1Masks {
				if vm := replaceI1(tryConf, m); vm != tryConf {
					variants = append(variants, vm)
				}
			}
			variants = append(variants, stripI1(tryConf))
		}
		for _, vc := range variants {
			hsMu.Lock()
			handshakeSeen = false
			hsMu.Unlock()
			if err := w.apply(vc, logf); err != nil {
				logf(fmt.Sprintf("Порт %d: подъём не удался: %v — следующий порт", p, err))
				break
			}
			fmt.Println("TUNNEL_UP")
			if waitHandshake(&hsMu, &handshakeSeen, 7*time.Second) {
				if p != port {
					logf(fmt.Sprintf("Handshake прошёл на порту %d (в конфиге был %d)", p, port))
				}
				success = true
				break attemptLoop
			}
			logf(fmt.Sprintf("Handshake нет на порту %d — пробую следующий вариант/порт", p))
			w.teardown()
			time.Sleep(1 * time.Second)
		}
	}
	if !success {
		w.teardown()
		fmt.Println("FATAL: handshake не прошёл ни на одном порту из списка — на этой сети перекрыты все живые WARP-порты; попробуй задать Endpoint вручную при генерации")
		os.Exit(1)
	}

	// stdin закрыт родителем = graceful teardown и выход (Sentor гасит сессию
	// закрытием stdin-пайпа; TerminateProcess остаётся аварийным путём —
	// хвосты тогда чистит cleanupStale при следующем запуске).
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
	} // пьём команды молча (резерв на будущее)
	logf("stdin закрыт — сносим туннель")
	w.teardown()
	fmt.Println("TUNNEL_DOWN")
}
