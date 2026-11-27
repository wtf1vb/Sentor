// Диспетчер пакетов — порт Go pwdttcore/dispatcher.go.
//
// Локальный UDP-сокет (127.0.0.1:port) читается readLoop'ом и раздаётся
// зарегистрированным слотам воркеров по round-robin (пакетами по chunkSize=12,
// при переполнении слота — перебор остальных); даунлинк из слотов летит через
// ReturnCh обратно клиенту. Пул буферов (Go pktPool) не нужен: Vec-аллокации
// дёшевы, семантика сохранена.
//
// КОНТРАКТ СОСЕДНИХ МОДУЛЕЙ wdtt/ (порт Go, snake_case):
//   crate::wdtt::core::log(msg) — порт log.Printf → события ядра (classify+фильтр)
//   crate::wdtt::stats::Stats — порт Go stats.go:
//       pub struct Stats {
//           pub total_bytes_up:     std::sync::atomic::AtomicI64,
//           pub total_bytes_down:   std::sync::atomic::AtomicI64,
//           pub active_connections: std::sync::atomic::AtomicI32,
//       }
//       impl Stats { pub fn new() -> Stats }
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::core::log;
use super::stats::Stats;

const RETURN_CH_BUF: usize = 512;
const CHUNK_SIZE: i32 = 12;
const READ_BUF: usize = 2048;

// WorkerSlot — порт Go WorkerSlot { ID, SendCh }: диспетчер хранит отправителя,
// воркер читает из парного Receiver.
pub struct WorkerSlot {
    pub id: i32,
    pub send_tx: SyncSender<Vec<u8>>,
}

pub struct Dispatcher {
    sock: UdpSocket,
    client_addr: Mutex<Option<SocketAddr>>,
    workers: Mutex<Vec<Arc<WorkerSlot>>>,
    rr_index: AtomicI32,
    rr_count: AtomicI32,
    pub(crate) return_tx: SyncSender<Vec<u8>>,
    cancel: Arc<AtomicBool>,
    stats: Arc<Stats>,
    threads: Mutex<Vec<std::thread::JoinHandle<()>>>,
}

impl Dispatcher {
    // NewDispatcher — сокет уже забинден ядром (Go net.ListenPacket в main.go).
    pub fn new(sock: UdpSocket, stats: Arc<Stats>, cancel: Arc<AtomicBool>) -> Arc<Dispatcher> {
        let _ = sock.set_read_timeout(Some(Duration::from_millis(250)));
        let (return_tx, return_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(RETURN_CH_BUF);
        let d = Arc::new(Dispatcher {
            sock,
            client_addr: Mutex::new(None),
            workers: Mutex::new(Vec::new()),
            rr_index: AtomicI32::new(0),
            rr_count: AtomicI32::new(0),
            return_tx,
            cancel,
            stats,
            threads: Mutex::new(Vec::new()),
        });
        let h_read = {
            let d = d.clone();
            std::thread::spawn(move || d.read_loop())
        };
        let h_write = {
            let d = d.clone();
            std::thread::spawn(move || d.write_loop(return_rx))
        };
        *d.threads.lock().unwrap_or_else(|e| e.into_inner()) = vec![h_read, h_write];
        d
    }

    // Shutdown — cancel + ожидание обоих циклов (Go: cancel + wg.Wait).
    pub fn shutdown(&self) {
        self.cancel.store(true, Ordering::SeqCst);
        let handles: Vec<_> = self.threads.lock().unwrap_or_else(|e| e.into_inner()).drain(..).collect();
        for h in handles {
            // паника цикла чтения/записи не должна уходить молча
            if let Err(p) = h.join() {
                crate::logging::log_add(
                    "wdtt",
                    &format!("[DISPATCHER] цикл запаниковал: {}", super::panic_msg(&p)),
                );
            }
        }
    }

    // Register — добавить слот воркера.
    pub fn register(&self, slot: Arc<WorkerSlot>) {
        let mut ws = self.workers.lock().unwrap_or_else(|e| e.into_inner());
        ws.push(slot.clone());
        log(&format!(
            "[ДИСП] Воркер #{} зарегистрирован (всего: {})",
            slot.id,
            ws.len()
        ));
    }

    // Unregister — убрать слот по идентичности (Go сравнивает указатели).
    pub fn unregister(&self, slot: &Arc<WorkerSlot>) {
        let mut ws = self.workers.lock().unwrap_or_else(|e| e.into_inner());
        ws.retain(|w| !Arc::ptr_eq(w, slot));
        log(&format!(
            "[ДИСП] Воркер #{} отключён (осталось: {})",
            slot.id,
            ws.len()
        ));
    }

    // readLoop — клиент → воркеры.
    fn read_loop(&self) {
        let mut buf = [0u8; READ_BUF];
        let mut uplink_drops: i64 = 0;
        loop {
            if self.cancel.load(Ordering::Relaxed) {
                return;
            }
            let (n, addr) = match self.sock.recv_from(&mut buf) {
                Ok(v) => v,
                Err(e) => {
                    if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut {
                        continue;
                    }
                    if self.cancel.load(Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
            };

            *self.client_addr.lock().unwrap_or_else(|e| e.into_inner()) = Some(addr);
            self.stats.total_bytes_up.fetch_add(n as i64, Ordering::Relaxed);

            let ws = self.workers.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if ws.is_empty() {
                continue;
            }
            let nw = ws.len();

            let mut sent = false;
            let idx = (self.rr_index.load(Ordering::Relaxed).max(0) as usize) % nw;
            let pkt = buf[..n].to_vec();

            // Основной путь: текущий слот round-robin (пакетами по chunkSize).
            if ws[idx].send_tx.try_send(pkt.clone()).is_ok() {
                sent = true;
                let count = self.rr_count.fetch_add(1, Ordering::Relaxed) + 1;
                if count >= CHUNK_SIZE {
                    self.rr_index
                        .store(((idx + 1) % nw) as i32, Ordering::Relaxed);
                    self.rr_count.store(0, Ordering::Relaxed);
                }
            } else {
                // Слот переполнен — перебираем остальные (Go: select default).
                for i in 1..nw {
                    let alt_idx = (idx + i) % nw;
                    if ws[alt_idx].send_tx.try_send(pkt.clone()).is_ok() {
                        sent = true;
                        self.rr_index.store(alt_idx as i32, Ordering::Relaxed);
                        self.rr_count.store(1, Ordering::Relaxed);
                        break;
                    }
                }
            }

            if !sent {
                self.rr_index
                    .store(((idx + 1) % nw) as i32, Ordering::Relaxed);
                self.rr_count.store(0, Ordering::Relaxed);
                // тишина при дропе аплинка делала потерю ненаблюдаемой: логируем
                // первую и каждую сотую, чтобы не заспамить лог
                uplink_drops += 1;
                if uplink_drops == 1 || uplink_drops % 100 == 0 {
                    log(&format!(
                        "[ДИСПЕТЧЕР] Аплинк дропнут (все слоты переполнены), всего: {}",
                        uplink_drops
                    ));
                }
            }
        }
    }

    // writeLoop — ReturnCh → клиент.
    fn write_loop(&self, return_rx: Receiver<Vec<u8>>) {
        let mut write_fails: i64 = 0;
        loop {
            if self.cancel.load(Ordering::Relaxed) {
                return;
            }
            let pkt = match return_rx.recv_timeout(Duration::from_millis(250)) {
                Ok(p) => p,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => return,
            };
            let addr = match *self.client_addr.lock().unwrap_or_else(|e| e.into_inner()) {
                Some(a) => a,
                None => continue, // Go: addrPtr == nil → дроп
            };
            match self.sock.send_to(&pkt, addr) {
                Ok(_) => {
                    write_fails = 0;
                    // недоставленный пакет не считаем в скачанный трафик
                    self.stats
                        .total_bytes_down
                        .fetch_add(pkt.len() as i64, Ordering::Relaxed);
                }
                Err(e) => {
                    if self.cancel.load(Ordering::Relaxed) {
                        return;
                    }
                    // ошибка записи в локальный сокет (ICMP-недоступность,
                    // переполнение буфера) — раньше молча глоталась
                    write_fails += 1;
                    if write_fails == 1 || write_fails % 50 == 0 {
                        log(&format!(
                            "[ДИСПЕТЧЕР] WriteTo клиенту не удался ({} раз подряд всего): {}",
                            write_fails, e
                        ));
                    }
                }
            }
        }
    }
}

// try_send_or_cancel — блокирующая (с отменой) отправка в ReturnCh:
// порт Go `select { case d.ReturnCh <- pkt: case <-sessCtx.Done(): }`.
pub(crate) fn try_send_or_cancel(
    tx: &SyncSender<Vec<u8>>,
    pkt: Vec<u8>,
    cancel: &AtomicBool,
) -> bool {
    let mut pkt = pkt;
    loop {
        // try_send по значению: пакет НЕ клонируется на каждой попытке —
        // при переполненной очереди возвращается нам же (buf переиспользуется),
        // тогда как pkt.clone() жёг CPU и аллокации каждый цикл
        match tx.try_send(pkt) {
            Ok(()) => return true,
            Err(TrySendError::Disconnected(back)) => {
                let _ = back;
                return false;
            }
            Err(TrySendError::Full(back)) => {
                pkt = back;
                if cancel.load(Ordering::Relaxed) {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }
}
