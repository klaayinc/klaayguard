pub fn retention_days() -> i64 {
    std::env::var("KLAAYGUARD_RETENTION_DAYS")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(30)
}

pub fn prune_batch_rows() -> i64 {
    std::env::var("KLAAYGUARD_PRUNE_BATCH_ROWS")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(5000)
}

pub fn max_db_mb() -> u64 {
    std::env::var("KLAAYGUARD_MAX_DB_MB")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(200)
}


