#[allow(dead_code)]
use crate::system::SystemError;
#[allow(unused_imports)]
use tauri::Manager;

#[allow(dead_code)]
pub fn show_main(app: &tauri::AppHandle) -> Result<(), SystemError> {
    if let Some(window) = app.get_webview_window("main") {
        window.show()?;
        Ok(())
    } else {
        Err(SystemError::InvalidState("main window not found"))
    }
}

#[allow(dead_code)]
pub fn hide_main(app: &tauri::AppHandle) -> Result<(), SystemError> {
    if let Some(window) = app.get_webview_window("main") {
        window.hide()?;
        Ok(())
    } else {
        Err(SystemError::InvalidState("main window not found"))
    }
}

#[allow(dead_code)]
pub fn focus_main(app: &tauri::AppHandle) -> Result<(), SystemError> {
    if let Some(window) = app.get_webview_window("main") {
        window.set_focus()?;
        Ok(())
    } else {
        Err(SystemError::InvalidState("main window not found"))
    }
}

#[allow(dead_code)]
pub fn toggle_main(app: &tauri::AppHandle) -> Result<(), SystemError> {
    if let Some(window) = app.get_webview_window("main") {
        if window.is_visible().unwrap_or(false) {
            window.hide()?;
        } else {
            window.show()?;
            let _ = window.set_focus();
        }
        Ok(())
    } else {
        Err(SystemError::InvalidState("main window not found"))
    }
}
