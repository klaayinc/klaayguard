use crate::system::{Callbacks, SystemError};

pub fn register_tray(app: &tauri::AppHandle, callbacks: &Callbacks) -> Result<(), SystemError> {
    let show_i = tauri::menu::MenuItem::with_id(app, "show", "Show", true, None::<&str>)?;
    let hide_i = tauri::menu::MenuItem::with_id(app, "hide", "Hide", true, None::<&str>)?;
    let menu = tauri::menu::Menu::with_items(app, &[&show_i, &hide_i])?;

    let cb_show = callbacks.on_show.clone();
    let cb_hide = callbacks.on_hide.clone();

    tauri::tray::TrayIconBuilder::new()
        .on_menu_event(move |app, event| match event.id.as_ref() {
            "show" => (cb_show)(app),
            "hide" => (cb_hide)(app),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| match event {
            tauri::tray::TrayIconEvent::Enter { .. } => {
                let _ = tray.set_tooltip(Some("KlaayGuard - Security Monitoring".to_string()));
            }
            tauri::tray::TrayIconEvent::Leave { .. } => {
                let _ = tray.set_tooltip(Some("".to_string()));
            }
            _ => {}
        })
        .icon(app.default_window_icon().unwrap().clone())
        .menu(&menu)
        .build(app)?;
    Ok(())
}
