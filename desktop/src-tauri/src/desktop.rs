use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tauri::{
    AppHandle, Manager, State, WebviewWindow,
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
};

const TRAY: &str = "deadwall-tray";
#[derive(Clone, Default)]
pub struct TraySetting(Arc<AtomicBool>);

fn restore(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

pub fn watch(window: WebviewWindow, setting: TraySetting) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("deadwall-tray".into())
        .spawn(move || {
            // Resize events do not consistently include the minimized transition.
            while window.app_handle().get_webview_window("main").is_some() {
                std::thread::sleep(std::time::Duration::from_millis(175));
                if setting.0.load(Ordering::Relaxed) {
                    let target = window.clone();
                    let checked = setting.clone();
                    let _ = window.app_handle().run_on_main_thread(move || {
                        if checked.0.load(Ordering::Relaxed)
                            && target.is_minimized().unwrap_or(false)
                            && target.is_visible().unwrap_or(false)
                        {
                            let _ = target.hide();
                        }
                    });
                }
            }
        })?;
    Ok(())
}

#[tauri::command]
pub fn set_minimize_to_tray(
    app: AppHandle,
    setting: State<'_, TraySetting>,
    enabled: bool,
) -> Result<(), String> {
    if !enabled {
        setting.0.store(false, Ordering::Relaxed);
        if let Some(tray) = app.tray_by_id(TRAY) {
            tray.set_visible(false).map_err(|error| error.to_string())?;
        }
        return Ok(());
    }
    if let Some(tray) = app.tray_by_id(TRAY) {
        tray.set_visible(true).map_err(|error| error.to_string())?;
    } else {
        let show = MenuItem::with_id(&app, "show-main", "Show deadWall", true, None::<&str>)
            .map_err(|error| error.to_string())?;
        let quit = MenuItem::with_id(&app, "quit-deadwall", "Quit deadWall", true, None::<&str>)
            .map_err(|error| error.to_string())?;
        let menu = Menu::with_items(&app, &[&show, &quit]).map_err(|error| error.to_string())?;
        let icon = app
            .default_window_icon()
            .ok_or("deadWall tray icon is unavailable")?
            .clone();
        TrayIconBuilder::with_id(TRAY)
            .icon(icon)
            .tooltip("deadWall")
            .menu(&menu)
            .show_menu_on_left_click(false)
            .on_menu_event(|app, event| match event.id().as_ref() {
                "show-main" => restore(app),
                "quit-deadwall" => app.exit(0),
                _ => {}
            })
            .on_tray_icon_event(|tray, event| {
                if let TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } = event
                {
                    restore(tray.app_handle());
                }
            })
            .build(&app)
            .map_err(|error| error.to_string())?;
    }
    setting.0.store(true, Ordering::Relaxed);
    Ok(())
}

#[tauri::command]
pub fn open_publisher_site() -> Result<(), String> {
    #[cfg(windows)]
    {
        use windows_sys::{
            Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL},
            w,
        };
        // This fixed URL is opened by an explicit footer click.
        let result = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                w!("open"),
                w!("https://digitalchaos.dev/"),
                std::ptr::null(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            )
        };
        if result as isize > 32 {
            Ok(())
        } else {
            Err("Windows could not open the publisher website.".into())
        }
    }
    #[cfg(not(windows))]
    {
        let opener = if cfg!(target_os = "macos") {
            "open"
        } else {
            "xdg-open"
        };
        let status = std::process::Command::new(opener)
            .arg("https://digitalchaos.dev/")
            .status()
            .map_err(|error| error.to_string())?;
        if status.success() {
            Ok(())
        } else {
            Err("Could not open the publisher website.".into())
        }
    }
}
