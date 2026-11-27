// Порт Go protocol.go: протокол GETCONF/AUTH поверх DTLS/TCP-соединения.
// (Устаревший трейт NetConn удалён: транспорт — WdttTransport из session.rs.)

// RequestConfig — запрос WireGuard-конфига у VPS-сервера.
// Go: func RequestConfig(conn net.Conn, localPort, deviceID, password string) (string, error)
// Порт принимает WdttTransport (read/write с таймаутами из session.rs).
pub fn request_config(
    conn: &dyn super::session::WdttTransport,
    local_port: &str,
    device_id: &str,
    password: &str,
) -> Result<String, String> {
    let payload = format!("GETCONF:{}|{}|{}", local_port, device_id, password);
    if let Err(e) = conn.write(payload.as_bytes(), std::time::Duration::from_secs(30)) {
        return Err(format!("отправка GETCONF: {}", e));
    }

    let mut acc: Vec<u8> = Vec::new();
    // DTLS-соединение потоковое: ответ мог прийти несколькими записями —
    // один Read обрезал конфиг, и «валидный» битый конфиг уезжал в UI.
    let quiet = std::time::Duration::from_millis(800);
    let overall = std::time::Duration::from_secs(15);
    let started = std::time::Instant::now();
    let mut got_data = false;
    // Потолок аккумулятора: сломанный/злонамеренный сервер, непрерывно льющий
    // данные в TCP, раздул бы acc до сотен МБ (15 с × пропускная способность)
    const ACC_CAP: usize = 1 << 20;
    loop {
        if started.elapsed() > overall {
            break;
        }
        let mut buf = [0u8; 4096];
        match conn.read(&mut buf, quiet) {
            Ok(0) => return Err("чтение ответа конфига: EOF".to_string()),
            Ok(n) => {
                if acc.len() + n > ACC_CAP {
                    return Err(format!("ответ конфига слишком большой (>{} КБ)", ACC_CAP / 1024));
                }
                acc.extend_from_slice(&buf[..n]);
                got_data = true;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                if !got_data {
                    return Err(format!("чтение ответа конфига: {}", e));
                }
                break;
            }
            Err(e) => return Err(format!("чтение ответа конфига: {}", e)),
        }
    }
    // Читаем до тишины: после первого куска ждём ещё 800 мс — ответ мог
    // прийти несколькими записями.

    let resp = String::from_utf8_lossy(&acc).into_owned();
    if resp.trim() == "NOCONF" {
        return Ok(String::new());
    }

    if let Some(reason) = resp.strip_prefix("DENIED:") {
        return Err(match reason {
            "wrong_password" => "FATAL_AUTH: неверный пароль подключения".to_string(),
            "expired" => "FATAL_AUTH: срок действия пароля истёк".to_string(),
            "device_mismatch" => "FATAL_AUTH: пароль привязан к другому устройству".to_string(),
            _ => format!("FATAL_AUTH: доступ запрещён ({})", reason),
        });
    }

    Ok(resp)
}

// SendAuth авторизует рабочую DTLS-сессию, которая не запрашивает WireGuard-конфиг.
// Go: func SendAuth(conn net.Conn, deviceID, password string) error
pub fn send_auth(
    conn: &dyn super::session::WdttTransport,
    device_id: &str,
    password: &str,
) -> Result<(), String> {
    let payload = format!("AUTH:{}|{}", device_id, password);
    if let Err(e) = conn.write(payload.as_bytes(), std::time::Duration::from_secs(30)) {
        return Err(format!("отправка AUTH: {}", e));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::session::WdttTransport;
    use std::collections::VecDeque;
    use std::io;
    use std::sync::Mutex;
    use std::time::Duration;

    // Вспомогательный коннект со «сценарием» ответов — эмуляция потокового
    // DTLS-соединения с таймаутами. Реализует WdttTransport (read/write &self).
    struct MockConn {
        script: Mutex<VecDeque<io::Result<Vec<u8>>>>,
        written: Mutex<Vec<u8>>,
    }

    impl MockConn {
        fn new(script: Vec<io::Result<Vec<u8>>>) -> Self {
            MockConn {
                script: Mutex::new(script.into()),
                written: Mutex::new(Vec::new()),
            }
        }
    }

    impl WdttTransport for MockConn {
        fn read(&self, buf: &mut [u8], _timeout: Duration) -> io::Result<usize> {
            let mut script = self.script.lock().unwrap_or_else(|e| e.into_inner());
            match script.pop_front() {
                Some(Ok(chunk)) => {
                    let n = chunk.len().min(buf.len());
                    buf[..n].copy_from_slice(&chunk[..n]);
                    Ok(n)
                }
                Some(Err(e)) => Err(e),
                None => Err(io::Error::new(io::ErrorKind::WouldBlock, "mock timeout")),
            }
        }
        fn write(&self, buf: &[u8], _timeout: Duration) -> io::Result<usize> {
            self.written.lock().unwrap_or_else(|e| e.into_inner()).extend_from_slice(buf);
            Ok(buf.len())
        }
        fn shutdown(&self) {}
    }

    fn timeout_err() -> io::Error {
        io::Error::new(io::ErrorKind::WouldBlock, "i/o timeout")
    }

    #[test]
    fn request_config_noconf() {
        let conn = MockConn::new(vec![Ok(b"NOCONF".to_vec()), Err(timeout_err())]);
        assert_eq!(request_config(&conn, "1080", "dev1", "pw").unwrap(), "");
        assert_eq!(*conn.written.lock().unwrap_or_else(|e| e.into_inner()), b"GETCONF:1080|dev1|pw");
    }

    #[test]
    fn request_config_chunked_answer() {
        let conn = MockConn::new(vec![
            Ok(b"GETCONF".to_vec()),
            Ok(b":ip=1.2.3.4".to_vec()),
            Err(timeout_err()),
        ]);
        assert_eq!(
            request_config(&conn, "1080", "dev1", "pw").unwrap(),
            "GETCONF:ip=1.2.3.4"
        );
    }

    #[test]
    fn request_config_denied() {
        let conn = MockConn::new(vec![Ok(b"DENIED:wrong_password".to_vec()), Err(timeout_err())]);
        assert_eq!(
            request_config(&conn, "1080", "dev1", "pw").unwrap_err(),
            "FATAL_AUTH: неверный пароль подключения"
        );
        let conn = MockConn::new(vec![Ok(b"DENIED:weird".to_vec()), Err(timeout_err())]);
        assert_eq!(
            request_config(&conn, "1080", "dev1", "pw").unwrap_err(),
            "FATAL_AUTH: доступ запрещён (weird)"
        );
    }

    #[test]
    fn request_config_first_read_timeout_is_error() {
        let conn = MockConn::new(vec![Err(timeout_err())]);
        let err = request_config(&conn, "1080", "dev1", "pw").unwrap_err();
        assert!(err.starts_with("чтение ответа конфига"));
    }

    #[test]
    fn request_config_eof_is_error() {
        // Go: conn.Read вернул (0, io.EOF) → err != nil, не таймаут → ошибка
        let conn = MockConn::new(vec![Ok(Vec::new()), Err(timeout_err())]);
        let err = request_config(&conn, "1080", "dev1", "pw").unwrap_err();
        assert_eq!(err, "чтение ответа конфига: EOF");
    }

    #[test]
    fn send_auth_payload() {
        let conn = MockConn::new(vec![]);
        send_auth(&conn, "dev1", "pw").unwrap();
        assert_eq!(*conn.written.lock().unwrap_or_else(|e| e.into_inner()), b"AUTH:dev1|pw");
    }
}
