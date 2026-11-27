// tauri-build with a custom manifest: requireAdministrator — как в Go-версии
// (winres.json: execution-level administrator). Без этого приложение не может
// писать в D:\NetTools (ACL — только Администраторы) и молча уезжает на C:.
// Плюс диагностический хук паники build-скрипта в лог-файл.
use std::panic;

// Версия подставляется из Cargo.toml (CARGO_PKG_VERSION): раньше она была
// захардкожена третьим местом бампа (Cargo.toml + tauri.conf.json + манифест).
// identifier — тот же, что в tauri.conf.json (ru.sentor.desktop): два разных
// «имени приложения» в одном бинаре затрудняли аудит.
//
// SENTOR_NO_ADMIN_MANIFEST=1 → asInvoker: cargo test строит тестовый harness
// тем же бином, и вшитый requireAdministrator давал os error 740 «требует
// повышения» — тесты не запускались вообще (run-tests.cmd). Релизной сборке
// переменная не задаётся — там остаётся requireAdministrator.
fn app_manifest() -> String {
    let ver = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "1.0.0".into());
    let level = if std::env::var_os("SENTOR_NO_ADMIN_MANIFEST").is_some() {
        "asInvoker"
    } else {
        "requireAdministrator"
    };
    APP_MANIFEST_TEMPLATE
        .replace("__VERSION__", &format!("{}.0", ver))
        .replace("__IDENTIFIER__", "ru.sentor.desktop")
        .replace("__EXEC_LEVEL__", level)
}

const APP_MANIFEST_TEMPLATE: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity name="__IDENTIFIER__" version="__VERSION__" type="win32" processorArchitecture="*"/>
  <description>Sentor</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v2">
    <security>
      <requestedPrivileges xmlns="urn:schemas-microsoft-com:asm.v3">
        <requestedExecutionLevel level="__EXEC_LEVEL__" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/>
      <supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"/>
      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
    </windowsSettings>
  </application>
</assembly>
"#;

// append_log — дописывает (не truncate): сообщение паники из хука не должно
// затираться финальной строкой результата
fn append_log(path: &std::path::Path, msg: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = f.write_all(msg.as_bytes());
    }
}

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let log_path = std::path::Path::new(&manifest_dir).join("build-script.log");
    let hook_path = log_path.clone();

    // Хук только ЛОГИРУЕТ панику и НЕ завершает процесс: exit(101) здесь
    // раньше делал ветку catch_unwind недостижимой (процесс умирал в хуке,
    // и запись «PANIC (caught…)» никогда не выполнялась)
    panic::set_hook(Box::new(move |info| {
        let msg = format!("PANIC: {}\n", info);
        append_log(&hook_path, &msg);
        eprintln!("{}", msg);
    }));

    let result = panic::catch_unwind(|| {
        let manifest = app_manifest();
        let windows = tauri_build::WindowsAttributes::new().app_manifest(&manifest);
        tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows))
            .expect("tauri build failed");
    });

    match result {
        Ok(()) => {
            // успешная сборка начинает лог заново
            let _ = std::fs::write(&log_path, "OK: tauri_build::build completed\n");
        }
        Err(_) => {
            append_log(&log_path, "PANIC (caught by catch_unwind)\n");
            std::process::exit(101);
        }
    }
}
