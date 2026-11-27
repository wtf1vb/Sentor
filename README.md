<div align="center">

# 🛡️ Sentor

**Универсальный VPN / прокси-клиент для Windows**

Один интерфейс для всего: ядра VPN, обфускация, обход блокировок,
маршрутизация и блокировка рекламы — без десятка отдельных программ.

![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-blue)
![Engine](https://img.shields.io/badge/Rust%20%2B%20Tauri-2-orange)
![VPN](https://img.shields.io/badge/cores-sing--box%20%7C%20Xray%20%7C%20AWG-red)
![License](https://img.shields.io/badge/license-GPL--3.0-green)

</div>

---

## ✨ Возможности

### 🔐 VPN-ядра

| Ядро | Что умеет |
|---|---|
| **sing-box / Xray** | VLESS, VMess, Trojan, Shadowsocks, Hysteria2 — включая REALITY, WS/gRPC/H2/XHTTP-транспорты и port hopping |
| **WARP / AmneziaWG** | через встроенный хелпер `SentorWarp.exe` — полная AWG-обфускация (Jc/S1-S2/H1-H4/I1-I5), генерация конфига, автоподбор endpoint |
| **TUN-режим** | полноценный туннель на wintun или системный прокси; цепочка xray+TUN для xhttp-ключей |

- 📥 **Подписки:** `vless://`, `vmess://`, `ss://`, `trojan://`, `hysteria2://`
  и клиентские ссылки **`happ://crypt…`**, **`incy://`**, **`v2raytun://`** (расшифровка встроена)
- 📋 **Форматы тел подписок:** base64, sing-box JSON, v2rayN JSON, Clash/Mihomo YAML

### 🚧 Обход блокировок

- **Zapret** (winws + WinDivert) — стратегии `.bat`, окно «Проверка стратегий» с автоподбором
- **TG WS Proxy** — прокси для Telegram со счётным релеем трафика

### 🕳 Собственные туннели

- **WDTT / CSQTT** — туннели через TURN/VK-звонки: пул воркеров, авто-решение
  VK Smart Captcha v2 (PoW + слайдер), DTLS-транспорт (WIP);
  WireGuard-конфиг от сервера поднимается через sing-box

### 🧰 Прочее

- 🚫 **Блокировка рекламы во всей системе** — локальный DNS-резолвер (список Hagezi PRO + свой), с fallback на исходные DNS
- 🗺 **Маршрутизация:** «всё через VPN» / «РФ напрямую» / избирательный режим (пресеты YouTube, Telegram, Discord, OpenAI)
- 🌍 Гео на глобусе, флаги стран, проверки доступности сервисов, счётчики трафика
- 🧷 Трей, single-instance, стражи прокси/DNS (восстановление системных настроек после краха)

---

## 📦 Установка

1. Скачай `Sentor_1.0.0.zip` из [Releases](../../releases) и распакуй.
2. Запусти `Sentor.exe` — приложение запросит права администратора (UAC).
3. Требуется **WebView2 Runtime** — в Windows 11 есть изначально; на Windows 10
   ставится как «Microsoft Edge WebView2 Runtime». `WebView2Loader.dll`
   должен лежать рядом с exe (в архиве уже лежит).

> Всё остальное приложение вшивает в себя и распаковывает само в папку
> инструментов (`D:\NetTools`, fallback: `C:\NetTools` → `%ProgramData%\NetTools`)
> при установке через UI: ядра VPN, Zapret, TG-прокси, списки маршрутизации,
> флаги стран. Кнопка «Обновить» качает свежие версии с GitHub, если нужен
> релиз новее вшитого.

Закрытие окна прячет приложение в трей — реальный выход: **«Выход» в меню трея**.

---

## 🛠 Сборка из исходников

**Требования:** Windows 10/11 x64, Rust (stable), mingw64 ([w64devkit](https://github.com/skeeto/w64devkit)), Go ≥ 1.27.

```bash
# 1) основное приложение (Rust + Tauri 2)
cd src-tauri
cargo build --release
# → src-tauri/target/release/sentor.exe
#    рядом нужен WebView2Loader.dll (mingw-сборка Tauri грузит его из папки exe)

# 2) хелпер WARP (Go), вшивается в приложение через include_bytes!
cd warp-helper
go build -o SentorWarp.exe .
# → скопировать в src-tauri/assets/vpn/SentorWarp.exe перед сборкой пункта 1
```

Профиль release: `strip + lto + codegen-units=1`. Манифест exe — `requireAdministrator`.

При правке ключевых материалов happ/incy/v2raytun не забудь перегенерировать
`.enc` (они вшиваются в exe): положи исходники в `src-tauri/assets/happcrypt/`
и выполни `cargo run --bin encrypt-keymat`.

---

## ⌨️ Командная строка

```
Sentor.exe              основное окно
Sentor.exe --checker    окно «Проверка стратегий»
```

Служебные режимы (не вызывать руками): `--relay`, `--proxy-guard`, `--adsdns`.

---

## 📁 Структура проекта

<details>
<summary>Дерево каталогов</summary>

```
├── frontend/            # UI — единый index.html (вшивается в exe)
├── src-tauri/           # бэкенд (Rust)
│   ├── src/             # сессии VPN/туннелей, DNS-блокировщик, подписки
│   │   └── bin/         # encrypt-keymat — шифрование keymat в *.enc
│   ├── assets/          # вшиваемые бинарники и ресурсы (see include_bytes!)
│   │   ├── vpn/         # sing-box, xray, wintun.dll, SentorWarp.exe
│   │   ├── cqstt/       # ядро CSQTT
│   │   ├── wdtt/        # ядро WDTT
│   │   └── happcrypt/   # keymat расшифровки клиентских ссылок (*.enc)
│   └── build.rs         # манифест exe (requireAdministrator)
├── warp-helper/         # SentorWarp.exe (Go, amneziawg-go 1.5)
└── release/             # готовая сборка (в git не входит)
```

</details>

---

## 🧩 Вшитые компоненты

| Компонент | Назначение | Источник | Лицензия |
|---|---|---|---|
| [sing-box](https://github.com/SagerNet/sing-box) | универсальное VPN-ядро | upstream | см. LICENSE в репозитории |
| [Xray-core](https://github.com/XTLS/Xray-core) | ядро Xray (VLESS/REALITY/XHTTP) | upstream | MPL-2.0 |
| [wintun](https://www.wintun.net/) | TUN-драйвер Windows | upstream | Wintun License |
| [zapret](https://github.com/bol-van/zapret) | обход DPI (winws + WinDivert) | upstream | см. репозиторий |
| WDTT core ([pwdtt-client](https://github.com/ildarmaga/pwdtt-client)) | туннель через TURN-звонки | upstream + обёртка | GPL-3.0 |
| csqtt-client | ядро CSQTT | закрытый бинарник поставщика | — |
| TG WS Proxy | прокси Telegram | закрытый бинарник | — |
| [warp-config-ru](https://github.com/AppsGanin/warp-config-ru) | параметры генерации WARP (маски I1, DNS) | заимствованы константы | MIT |

---

## ⚠️ Дисклеймер

Проект создан для личного использования. Всё программное обеспечение
принадлежит его авторам; ответственности за использование несёт пользователь.

---

## 📄 Лицензия

[GNU GPL-3.0](LICENSE)
