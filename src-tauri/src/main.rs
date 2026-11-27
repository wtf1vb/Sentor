// Sentor — VPN/proxy desktop client (Rust + Tauri 2). Stage 5: tray, single-instance,
// --checker / --relay modes.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod adsdns;
mod checker;
mod commands;
mod conn;
mod cqstt_session;
mod geo;
mod happcrypt;
mod logging;
mod models;
mod paths;
mod ping;
mod relay;
mod route_rules;
mod state;
mod store;
mod subfetch;
mod subparse;
mod sysinfo;
mod sysproxy;
mod tools;
mod vpnconfig;
mod vpnlinks;
mod warp;
mod wdtt;
mod wdtt_session;

use std::sync::atomic::{AtomicBool, Ordering};

use tauri::Manager;

// «Выход» из меню трея: закрытие окна — это выход, а не сворачивание
static TRAY_EXIT: AtomicBool = AtomicBool::new(false);
// режим окна «Проверка стратегий» (--checker)
static CHECKER_MODE: AtomicBool = AtomicBool::new(false);

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Счётный релей Telegram — отдельный лёгкий процесс без GUI:
    // Sentor.exe --relay <listenPort> <backendPort> <statsFile>
    if args.len() > 4 && args[1] == "--relay" {
        relay::run_relay_process(&args[2], &args[3], &args[4]);
        return;
    }

    // DNS-блокировщик рекламы — отдельный лёгкий процесс без GUI:
    // Sentor.exe --adsdns <toolsDir>
    if args.len() > 2 && args[1] == "--adsdns" {
        adsdns::run_dns_process(&args[2]);
        return;
    }

    // Страж системного прокси — переживает force-kill родителя:
    // Sentor.exe --proxy-guard <parentPid> <toolsDir> [dns]
    if args.len() > 3 && args[1] == "--proxy-guard" {
        if let Ok(pid) = args[2].parse::<u32>() {
            let mode = args.get(4).map(|s| s.as_str()).unwrap_or("");
            sysproxy::run_proxy_guard(pid, &args[3], mode);
        }
        return;
    }

    let checker_mode = args.len() > 1 && args[1] == "--checker";
    CHECKER_MODE.store(checker_mode, Ordering::Relaxed);

    let is_checker = checker_mode;

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(move |app, args, _cwd| {
            // второй запуск при живом экземпляре = показать окно; --checker во
            // втором экземпляре должен открывать окно проверки в первом
            // (раньше аргументы игнорировались и окно проверки не открывалось)
            let wants_checker = args.iter().skip(1).any(|a| a == "--checker");
            let label = if wants_checker || is_checker { "checker" } else { "main" };
            if let Some(w) = app.get_webview_window(label) {
                let _ = w.unminimize();
                let _ = w.show();
                let _ = w.set_focus();
            } else if wants_checker {
                // open_checker теперь async-команда: просто вызвать её нельзя —
                // future создастся и тут же дропнется, не выполнившись. Спавним.
                let _ = tauri::async_runtime::spawn(commands::open_checker(app.clone()));
            }
        }))
        .manage(std::sync::Arc::new(state::AppState::new()))
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // Закрытие главного окна прячет приложение в фон: VPN, WDTT
                // и счётные релеи продолжают работать. Окно проверки закрывается
                // молча — но синхронно глушим winws от прерванного теста и
                // возвращаем прежний профиль; «Выход» в трее ставит TRAY_EXIT.
                if CHECKER_MODE.load(Ordering::Relaxed) || window.label() == "checker" {
                    let state = window.app_handle().state::<std::sync::Arc<state::AppState>>();
                    let tools = state.tools();
                    if CHECKER_MODE.load(Ordering::Relaxed) {
                        // единственное окно приложения (--checker) закрывается
                        // вместе с процессом — успеть вернуть прежний профиль
                        // можно только синхронно
                        checker::stop_checker_for_close(&tools);
                    } else {
                        // второстепенное окно при живом приложении: уборка
                        // (taskkill + ожидания, до ~19 с) уходит в фон, чтобы не
                        // морозить главный поток; окно закрывается сразу
                        std::thread::spawn(move || checker::stop_checker_for_close(&tools));
                    }
                    return;
                }
                if !TRAY_EXIT.load(Ordering::Relaxed) {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .setup(move |app| {
            // вспомнить порты прошлой сессии; хвосты прошлого падения:
            // если процесс упал с включённым системным прокси — вернуть настройки
            let state = app.state::<std::sync::Arc<state::AppState>>();
            let tools = state.tools();
            conn::load_vpn_ports(&tools);
            sysproxy::cleanup_stale_system_proxy(&tools);
            // блокировка рекламы «всегда»: тумблер ON → поднять/подхватить
            // DNS-блокировщик; OFF → убрать хвосты (наши DNS на адаптерах)
            adsdns::ensure_on_startup(&tools);
            // хвост прошлого падения: конфиг с приватным ключом WARP живёт
            // только внутри сессии подключения — при крахе процесса убираем
            // его, чтобы ключ не оставался на диске (.json — старый sing-box
            // формат, .conf — текущий для SentorWarp)
            let _ = std::fs::remove_file(paths::vpn_dir(&tools).join("config_warp.json"));
            let _ = std::fs::remove_file(paths::vpn_dir(&tools).join("config_warp.conf"));
            // хендл для warpLog-событий из logging::log_add (строки компонента
            // «warp» дублируются событием на страницу WARP). Без него
            // APP_HANDLE.get() в log_add всегда None, и живой лог WARP в UI
            // не обновлялся никогда
            logging::set_app_handle(app.handle().clone());
            // хвосты pwdtt-wg: битые адаптеры/маршруты прошлой сессии (фон, как в Go)
            wdtt_session::set_app_handle(app.handle().clone());
            // CSQTT: хендл для событий + хвосты прошлой сессии (крах мог оставить
            // адаптер CSQTT/маршруты — cleanup чистит их; зависший csqtt-client добивается)
            cqstt_session::set_app_handle(app.handle().clone());
            // checker-инстанс уборку НЕ делает: он живёт ПАРАЛЛЕЛЬНО главному
            // приложению, и его taskkill /IM csqtt-client.exe + снос маршрутов
            // убивали живую сессию основного окна
            if !is_checker {
                std::thread::spawn(wdtt_session::startup_cleanup);
                std::thread::spawn(cqstt_session::startup_cleanup);
            }
            // TgWsProxy переживает закрытие приложения — если он работает,
            // сразу поднимаем счётный релей, чтобы порт и счётчик не отваливались
            if sysinfo::process_running(paths::TG_EXE_NAME) {
                if let Err(e) = tools::ensure_relay(&state) {
                    logging::log_add("tgproxy", &format!("счётный релей не запустился: {}", e));
                }
            }
            // диагностический зонд: через 3 с отчёт о шиме/IPC в diag.log
            let probe_js = r#"
                setTimeout(() => {
                    const report = (d) => { try { window.__TAURI__.core.invoke('diag_report', { data: JSON.stringify(d) }); } catch (e) { try { window.__TAURI__.core.invoke('diag_report', { data: 'PROBE-FAIL: ' + String(e) }); } catch (e2) {} } };
                    const diag = { hasTauri: !!window.__TAURI__, hasGo: !!(window.go && window.go.main && window.go.main.App), hasInvoke: !!(window.__TAURI__ && window.__TAURI__.core && window.__TAURI__.core.invoke) };
                    if (diag.hasGo && diag.hasInvoke) {
                        window.go.main.App.GetStatus().then(
                            (s) => report({ ...diag, getStatusOk: true, toolsDir: s && s.toolsDir }),
                            (e) => report({ ...diag, getStatusErr: String(e) })
                        );
                    } else {
                        report(diag);
                    }
                }, 3000);
            "#;
            if is_checker {
                tauri::WebviewWindowBuilder::new(
                    app,
                    "checker",
                    tauri::WebviewUrl::App("checker/index.html".into()),
                )
                .title("Sentor — Проверка стратегий")
                .inner_size(1150.0, 740.0)
                .center()
                .build()?;
            } else {
                let w = tauri::WebviewWindowBuilder::new(
                    app,
                    "main",
                    tauri::WebviewUrl::App("index.html".into()),
                )
                .title("Sentor")
                .inner_size(1020.0, 700.0)
                .center()
                .build()?;
                let _ = w.eval(probe_js);
                build_tray(app)?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // утилиты
            commands::ping,
            commands::open_url,
            commands::diag_report,
            // статус / трафик
            commands::get_status,
            commands::get_traffic,
            commands::verify_install,
            commands::check_updates,
            commands::open_tools_folder,
            // логи
            commands::get_logs,
            commands::save_logs_file,
            commands::clear_logs,
            // инструменты
            commands::install_zapret,
            commands::update_zapret,
            commands::install_tg_proxy,
            commands::update_tg_proxy,
            commands::start_strategy,
            commands::stop_zapret,
            commands::start_tg_proxy,
            commands::stop_tg_proxy,
            commands::add_to_telegram,
            commands::tool_sources,
            // checker
            commands::checker_start,
            commands::checker_stop,
            commands::checker_state,
            commands::checker_select,
            commands::open_checker,
            // pwdtt
            commands::pwdtt_servers,
            commands::pwdtt_save_server,
            commands::pwdtt_remove_server,
            commands::pwdtt_connect,
            commands::pwdtt_disconnect,
            commands::pwdtt_import_link,
            commands::pwdtt_send_captcha,
            commands::pwdtt_status,
            commands::pwdtt_log,
            // cqstt
            commands::cqstt_servers,
            commands::cqstt_save_server,
            commands::cqstt_remove_server,
            commands::cqstt_connect,
            commands::cqstt_disconnect,
            commands::cqstt_import_link,
            commands::cqstt_send_captcha,
            commands::cqstt_status,
            commands::cqstt_log,
            // vpn
            commands::vpn_list,
            commands::vpn_list_subscriptions,
            commands::vpn_get_settings,
            commands::vpn_set_settings,
            commands::vpn_remove,
            commands::vpn_remove_subscription,
            commands::vpn_add_link,
            commands::vpn_add_subscription,
            commands::vpn_add_warp_config,
            commands::vpn_connect,
            commands::vpn_disconnect,
            commands::vpn_export_warp_conf,
            commands::vpn_import_warp_conf,
            commands::vpn_generate_warp_conf,
            commands::vpn_install_core,
            commands::vpn_refresh_subscription,
            commands::vpn_refresh_all_subscriptions,
            commands::vpn_ping,
            commands::vpn_ping_through,
            commands::vpn_check_ip,
            commands::vpn_status,
            commands::vpn_traffic,
            commands::vpn_geo,
            commands::vpn_servers_geo,
            commands::vpn_services,
            commands::vpn_flags,
            commands::vpn_start_service_checks,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

// beforeClose (реальный выход через «Выход» в трее): гасим VPN с системным
// прокси, глушим тестовые ядра пинговки, сохраняем счётчик трафика, и если
// работает релей TG-прокси — спрашиваем, выключать ли прокси при выходе.
fn graceful_exit(app: &tauri::AppHandle) {
    // Обратная связь ДО уборки: kill_core/wdtt/cqstt shutdown занимают до ~15 с,
    // и без этого «Выход» выглядел мёртвой кнопкой.
    if let Some(tray) = app.tray_by_id("sentor-tray") {
        let _ = tray.set_tooltip(Some("Sentor — выключаю туннели…"));
    }
    let state = app.state::<std::sync::Arc<state::AppState>>();
    let tools = state.tools();
    // VPN не должен переживать закрытие приложения: иначе после смерти ядра
    // весь трафик системы пойдёт в мёртвый локальный порт — «интернет отвалится»
    state.conn.stop(app);
            // pwdttShutdown: гасим WDTT-ядро и снимаем pwdtt-wg интерфейс/маршруты —
            // раньше вызов терялся, и после выхода оставались TUN-адаптер и auto_route
            // «в никуда» (интернет отваливался до следующего запуска)
            wdtt_session::shutdown();
            // CSQTT: гасим сессию и чистим маршруты/NRPT (TUN общий с VPN)
            cqstt_session::shutdown();
    // временные ядра «Теста задержки» тоже не должны переживать выход
    ping::vpn_ping_kill_all();
    // Сохраняем базу счётчика релея: следующий запуск продолжит с корректного места.
    {
        let mut st = state.traffic.lock().unwrap_or_else(|e| e.into_inner());
        if st.loaded {
            store::save_traffic_totals(
                &tools,
                *st.totals.get("telegram").unwrap_or(&0),
                st.relay_pid,
                st.relay_prev,
            );
            st.last_save = Some(std::time::Instant::now());
        }
    }
    if !tools::relay_running(&tools) {
        app.exit(0);
        return;
    }
    let answer = rfd::MessageDialog::new()
        .set_title("Sentor — выход")
        .set_description("TG-прокси сейчас работает через релей.\nВыключить его при выходе?")
        .set_buttons(rfd::MessageButtons::YesNo)
        .show();
    if answer == rfd::MessageDialogResult::Yes {
        let _ = tools::run_hidden("taskkill", &["/F", "/IM", paths::TG_EXE_NAME]);
        tools::kill_relay(&tools);
    }
    app.exit(0);
}

// Трей: закрытие окна НЕ завершает Sentor — окно прячется, а VPN, WDTT и
// счётные релеи продолжают работать в фоне. Реальный выход — «Выход» в меню.
fn build_tray(app: &tauri::App) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
    use tauri::tray::TrayIconBuilder;

    let open = MenuItem::with_id(app, "open", "Открыть Sentor", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &sep, &quit])?;

    let icon = tauri::image::Image::from_bytes(include_bytes!("../icons/icon.ico"))?;

    TrayIconBuilder::with_id("sentor-tray")
        .icon(icon)
        .tooltip("Sentor — работает в фоне")
        .menu(&menu)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.unminimize();
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
            "quit" => {
                TRAY_EXIT.store(true, Ordering::Relaxed);
                graceful_exit(app);
            }
            _ => {}
        })
        .build(app)?;
    Ok(())
}
