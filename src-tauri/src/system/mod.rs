use std::sync::Arc;

#[derive(thiserror::Error, Debug)]
pub enum SystemError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tauri: {0}")]
    Tauri(#[from] tauri::Error),
    #[error("invalid_state: {0}")]
    InvalidState(&'static str),
}

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

pub mod launch_agent;
pub mod tray;
pub mod window;
