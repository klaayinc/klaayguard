use crate::system::SystemError;
#[allow(unused_imports)]
use tauri::Manager;

pub fn show_main(app: &tauri::AppHandle) -> Result<(), SystemError> {
    if let Some(window) = app.get_webview_window("main") {
        window.show()?;
        Ok(())
    } else {
        Err(SystemError::InvalidState("main window not found"))
    }
}

pub fn hide_main(app: &tauri::AppHandle) -> Result<(), SystemError> {
    if let Some(window) = app.get_webview_window("main") {
        window.hide()?;
        Ok(())
    } else {
        Err(SystemError::InvalidState("main window not found"))
    }
}

pub fn focus_main(app: &tauri::AppHandle) -> Result<(), SystemError> {
    if let Some(window) = app.get_webview_window("main") {
        window.set_focus()?;
        Ok(())
    } else {
        Err(SystemError::InvalidState("main window not found"))
    }
}
