pub fn wake_gap_seconds() -> u64 {
    std::env::var("KLAAYGUARD_WAKE_GAP_SECONDS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(300)
}

pub fn collection_interval_seconds() -> u64 {
    std::env::var("KLAAYGUARD_COLLECTION_INTERVAL_SECONDS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(900)
}

pub fn upload_interval_seconds() -> u64 {
    std::env::var("KLAAYGUARD_UPLOAD_INTERVAL_SECONDS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(900)
}

pub fn retention_interval_seconds() -> u64 {
    std::env::var("KLAAYGUARD_RETENTION_INTERVAL_SECONDS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(24 * 60 * 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    use serial_test::serial;

    #[test]
    #[serial]
    fn defaults_apply_when_env_missing() {
        std::env::remove_var("KLAAYGUARD_WAKE_GAP_SECONDS");
        std::env::remove_var("KLAAYGUARD_COLLECTION_INTERVAL_SECONDS");
        std::env::remove_var("KLAAYGUARD_UPLOAD_INTERVAL_SECONDS");
        std::env::remove_var("KLAAYGUARD_RETENTION_INTERVAL_SECONDS");
        assert_eq!(wake_gap_seconds(), 300);
        assert_eq!(collection_interval_seconds(), 900);
        assert_eq!(upload_interval_seconds(), 900);
        assert_eq!(retention_interval_seconds(), 24 * 60 * 60);
    }

    #[test]
    #[serial]
    fn parses_env_overrides() {
        std::env::set_var("KLAAYGUARD_WAKE_GAP_SECONDS", "10");
        std::env::set_var("KLAAYGUARD_COLLECTION_INTERVAL_SECONDS", "11");
        std::env::set_var("KLAAYGUARD_UPLOAD_INTERVAL_SECONDS", "12");
        std::env::set_var("KLAAYGUARD_RETENTION_INTERVAL_SECONDS", "13");
        assert_eq!(wake_gap_seconds(), 10);
        assert_eq!(collection_interval_seconds(), 11);
        assert_eq!(upload_interval_seconds(), 12);
        assert_eq!(retention_interval_seconds(), 13);
        // cleanup
        std::env::remove_var("KLAAYGUARD_WAKE_GAP_SECONDS");
        std::env::remove_var("KLAAYGUARD_COLLECTION_INTERVAL_SECONDS");
        std::env::remove_var("KLAAYGUARD_UPLOAD_INTERVAL_SECONDS");
        std::env::remove_var("KLAAYGUARD_RETENTION_INTERVAL_SECONDS");
    }
}
