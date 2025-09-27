use std::sync::Arc;

#[allow(dead_code)]
#[derive(thiserror::Error, Debug)]
pub enum SystemError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tauri: {0}")]
    Tauri(#[from] tauri::Error),
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
    #[error("invalid_state: {0}")]
    InvalidState(&'static str),
    #[error("other: {0}")]
    Other(String),
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct Callbacks {
    pub on_show: Arc<dyn Fn(&tauri::AppHandle) + Send + Sync>,
    pub on_hide: Arc<dyn Fn(&tauri::AppHandle) + Send + Sync>,
}

impl Callbacks {
    pub fn new<F1, F2>(on_show: F1, on_hide: F2) -> Self
    where
        F1: Fn(&tauri::AppHandle) + Send + Sync + 'static,
        F2: Fn(&tauri::AppHandle) + Send + Sync + 'static,
    {
        Self {
            on_show: Arc::new(on_show),
            on_hide: Arc::new(on_hide),
        }
    }
}

#[allow(dead_code)]
pub struct SystemIntegration {
    app: tauri::AppHandle,
}

impl SystemIntegration {
    #[allow(dead_code)]
    pub fn init(app: &tauri::AppHandle, callbacks: Callbacks) -> Result<Self, SystemError> {
        tray::register_tray(app, &callbacks)?;
        Ok(Self { app: app.clone() })
    }

    #[allow(dead_code)]
    pub fn show_main_window(&self) -> Result<(), SystemError> {
        window::show_main(&self.app)
    }

    #[allow(dead_code)]
    pub fn hide_main_window(&self) -> Result<(), SystemError> {
        window::hide_main(&self.app)
    }

    #[allow(dead_code)]
    pub fn focus_main_window(&self) -> Result<(), SystemError> {
        window::focus_main(&self.app)
    }

    #[allow(dead_code)]
    pub fn toggle_main_window(&self) -> Result<(), SystemError> {
        window::toggle_main(&self.app)
    }
}

pub mod launch_agent;
pub mod tray;
pub mod window;

// keep commands in submodule; reference from crate path
