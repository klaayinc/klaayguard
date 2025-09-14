-- Create queued_data table for storing data that needs to be sent to API
CREATE TABLE IF NOT EXISTS queued_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_uuid TEXT NOT NULL,
    data TEXT NOT NULL, -- JSON data
    created_at TEXT NOT NULL, -- ISO 8601 timestamp
    retry_count INTEGER NOT NULL DEFAULT 0,
    last_attempt TEXT -- ISO 8601 timestamp
);

-- Create sync_status table for tracking sync status
CREATE TABLE IF NOT EXISTS sync_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_uuid TEXT NOT NULL UNIQUE,
    last_successful_sync TEXT NOT NULL, -- ISO 8601 timestamp
    last_attempt TEXT NOT NULL, -- ISO 8601 timestamp
    consecutive_failures INTEGER NOT NULL DEFAULT 0
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_queued_data_device_uuid ON queued_data(device_uuid);
CREATE INDEX IF NOT EXISTS idx_queued_data_created_at ON queued_data(created_at);
CREATE INDEX IF NOT EXISTS idx_queued_data_retry_count ON queued_data(retry_count);
CREATE INDEX IF NOT EXISTS idx_sync_status_device_uuid ON sync_status(device_uuid);
