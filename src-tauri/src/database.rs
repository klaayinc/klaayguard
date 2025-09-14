use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::SqlitePool, Row};
use tauri::{AppHandle, Manager};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct QueuedData {
    pub id: i64,
    pub device_uuid: String,
    pub data: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub retry_count: i32,
    pub last_attempt: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SyncStatus {
    pub id: i64,
    pub device_uuid: String,
    pub last_successful_sync: DateTime<Utc>,
    pub last_attempt: DateTime<Utc>,
    pub consecutive_failures: i32,
}

pub struct Database {
    pool: SqlitePool,
}

impl Database {
    pub async fn new(app_handle: &AppHandle) -> Result<Self> {
        let app_data_dir = app_handle
            .path()
            .app_data_dir()
            .map_err(|e| anyhow::anyhow!("Failed to get app data dir: {}", e))?;

        std::fs::create_dir_all(&app_data_dir)
            .map_err(|e| anyhow::anyhow!("Failed to create app data dir: {}", e))?;

        let database_path = app_data_dir.join("klaayguard.db");
        let database_url = format!("sqlite://{}", database_path.display());

        let pool = SqlitePool::connect(&database_url).await?;

        // Create tables manually instead of using migrations for now
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS queued_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_uuid TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL,
                retry_count INTEGER NOT NULL DEFAULT 0,
                last_attempt TEXT
            )",
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS sync_status (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_uuid TEXT NOT NULL UNIQUE,
                last_successful_sync TEXT NOT NULL,
                last_attempt TEXT NOT NULL,
                consecutive_failures INTEGER NOT NULL DEFAULT 0
            )",
        )
        .execute(&pool)
        .await?;

        Ok(Database { pool })
    }

    // Simple constructor for immediate initialization
    pub fn new_simple(_app_handle: &AppHandle) -> Self {
        // Create a simple in-memory database for basic functionality
        // This will be replaced with proper database initialization later
        let rt = tokio::runtime::Runtime::new().unwrap();
        let pool = rt.block_on(async { SqlitePool::connect("sqlite::memory:").await.unwrap() });

        Database { pool }
    }

    pub async fn queue_data(&self, device_uuid: &str, data: serde_json::Value) -> Result<i64> {
        let result = sqlx::query(
            "INSERT INTO queued_data (device_uuid, data, created_at, retry_count) VALUES (?, ?, ?, 0)"
        )
        .bind(device_uuid)
        .bind(data)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    pub async fn get_pending_data(&self, limit: i32) -> Result<Vec<QueuedData>> {
        let rows = sqlx::query(
            "SELECT id, device_uuid, data, created_at, retry_count, last_attempt 
             FROM queued_data 
             WHERE retry_count < 5 
             ORDER BY created_at ASC 
             LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        let mut queued_data = Vec::new();
        for row in rows {
            queued_data.push(QueuedData {
                id: row.get("id"),
                device_uuid: row.get("device_uuid"),
                data: serde_json::from_str(&row.get::<String, _>("data"))?,
                created_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))?
                    .with_timezone(&Utc),
                retry_count: row.get("retry_count"),
                last_attempt: row.get::<Option<String>, _>("last_attempt").map(|dt| {
                    DateTime::parse_from_rfc3339(&dt)
                        .unwrap()
                        .with_timezone(&Utc)
                }),
            });
        }

        Ok(queued_data)
    }

    pub async fn mark_data_sent(&self, id: i64) -> Result<()> {
        sqlx::query("DELETE FROM queued_data WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn mark_data_failed(&self, id: i64) -> Result<()> {
        sqlx::query(
            "UPDATE queued_data SET retry_count = retry_count + 1, last_attempt = ? WHERE id = ?",
        )
        .bind(Utc::now().to_rfc3339())
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_sync_status(&self, device_uuid: &str, success: bool) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        if success {
            sqlx::query(
                "INSERT OR REPLACE INTO sync_status (device_uuid, last_successful_sync, last_attempt, consecutive_failures) 
                 VALUES (?, ?, ?, 0)"
            )
            .bind(device_uuid)
            .bind(&now)
            .bind(&now)
            .execute(&self.pool)
            .await?;
        } else {
            // Get current failure count
            let current_failures =
                sqlx::query("SELECT consecutive_failures FROM sync_status WHERE device_uuid = ?")
                    .bind(device_uuid)
                    .fetch_optional(&self.pool)
                    .await?
                    .map(|row| row.get::<i32, _>("consecutive_failures"))
                    .unwrap_or(0);

            // Get last successful sync
            let last_successful_sync =
                sqlx::query("SELECT last_successful_sync FROM sync_status WHERE device_uuid = ?")
                    .bind(device_uuid)
                    .fetch_optional(&self.pool)
                    .await?
                    .map(|row| row.get::<String, _>("last_successful_sync"));

            sqlx::query(
                "INSERT OR REPLACE INTO sync_status (device_uuid, last_successful_sync, last_attempt, consecutive_failures) 
                 VALUES (?, ?, ?, ?)"
            )
            .bind(device_uuid)
            .bind(last_successful_sync)
            .bind(&now)
            .bind(current_failures + 1)
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    pub async fn get_sync_status(&self, device_uuid: &str) -> Result<Option<SyncStatus>> {
        let row = sqlx::query(
            "SELECT id, device_uuid, last_successful_sync, last_attempt, consecutive_failures 
             FROM sync_status WHERE device_uuid = ?",
        )
        .bind(device_uuid)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            Ok(Some(SyncStatus {
                id: row.get("id"),
                device_uuid: row.get("device_uuid"),
                last_successful_sync: DateTime::parse_from_rfc3339(
                    &row.get::<String, _>("last_successful_sync"),
                )?
                .with_timezone(&Utc),
                last_attempt: DateTime::parse_from_rfc3339(&row.get::<String, _>("last_attempt"))?
                    .with_timezone(&Utc),
                consecutive_failures: row.get("consecutive_failures"),
            }))
        } else {
            Ok(None)
        }
    }

    pub async fn cleanup_old_data(&self, days_old: i32) -> Result<()> {
        let cutoff_date = Utc::now() - chrono::Duration::days(days_old as i64);

        sqlx::query("DELETE FROM queued_data WHERE created_at < ?")
            .bind(cutoff_date.to_rfc3339())
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
