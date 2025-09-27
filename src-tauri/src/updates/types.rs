#[derive(Debug)]
pub enum UpdateError {
    Http(String),
    Io(String),
    InvalidResponse(String),
    VersionParse(String),
    System(String),
}

impl std::fmt::Display for UpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdateError::Http(s) => write!(f, "http error: {}", s),
            UpdateError::Io(s) => write!(f, "io error: {}", s),
            UpdateError::InvalidResponse(s) => write!(f, "invalid response: {}", s),
            UpdateError::VersionParse(s) => write!(f, "version parse error: {}", s),
            UpdateError::System(s) => write!(f, "system error: {}", s),
        }
    }
}

impl From<reqwest::Error> for UpdateError {
    fn from(e: reqwest::Error) -> Self {
        UpdateError::Http(e.to_string())
    }
}

impl From<std::io::Error> for UpdateError {
    fn from(e: std::io::Error) -> Self {
        UpdateError::Io(e.to_string())
    }
}


