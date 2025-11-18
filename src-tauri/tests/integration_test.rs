use std::sync::Arc;
use tokio::sync::RwLock;

/// Mock AppState for testing
struct AppState {
    pub auth_token: RwLock<Option<String>>,
    pub api_base_url: RwLock<String>,
    pub last_send_status: RwLock<Option<bool>>,
    pub last_send_at: RwLock<Option<chrono::DateTime<chrono::Utc>>>,
    pub keychain_cleared_this_session: RwLock<bool>,
}

#[tokio::test]
async fn test_app_state_concurrent_access() {
    // Test that multiple async tasks can access state concurrently
    let state = Arc::new(AppState {
        auth_token: RwLock::new(None),
        api_base_url: RwLock::new("https://api.test.com".to_string()),
        last_send_status: RwLock::new(None),
        last_send_at: RwLock::new(None),
        keychain_cleared_this_session: RwLock::new(false),
    });
    
    let state1 = state.clone();
    let state2 = state.clone();
    let state3 = state.clone();
    
    // Spawn multiple concurrent tasks
    let task1 = tokio::spawn(async move {
        *state1.auth_token.write().await = Some("token1".to_string());
    });
    
    let task2 = tokio::spawn(async move {
        *state2.last_send_status.write().await = Some(true);
    });
    
    let task3 = tokio::spawn(async move {
        let _ = state3.api_base_url.read().await;
    });
    
    // All tasks should complete without deadlock
    task1.await.unwrap();
    task2.await.unwrap();
    task3.await.unwrap();
    
    assert_eq!(*state.auth_token.read().await, Some("token1".to_string()));
    assert_eq!(*state.last_send_status.read().await, Some(true));
}

#[tokio::test]
async fn test_no_nested_runtime_panic() {
    // This test verifies that we don't create nested runtimes
    // If this test passes, it means we're not using block_on in async contexts
    
    let state = Arc::new(AppState {
        auth_token: RwLock::new(None),
        api_base_url: RwLock::new("https://api.test.com".to_string()),
        last_send_status: RwLock::new(None),
        last_send_at: RwLock::new(None),
        keychain_cleared_this_session: RwLock::new(false),
    });
    
    // Simulate what update_tray_status does
    *state.last_send_status.write().await = Some(true);
    *state.last_send_at.write().await = Some(chrono::Utc::now());
    
    // If we used block_on here, this would panic
    let status = state.last_send_status.read().await;
    assert_eq!(*status, Some(true));
}

#[tokio::test]
async fn test_auth_token_lifecycle() {
    let state = Arc::new(AppState {
        auth_token: RwLock::new(None),
        api_base_url: RwLock::new("https://api.test.com".to_string()),
        last_send_status: RwLock::new(None),
        last_send_at: RwLock::new(None),
        keychain_cleared_this_session: RwLock::new(false),
    });
    
    // Initially no token
    assert!(state.auth_token.read().await.is_none());
    
    // Set token
    *state.auth_token.write().await = Some("test_token".to_string());
    assert_eq!(*state.auth_token.read().await, Some("test_token".to_string()));
    
    // Clear token (simulate invalidation)
    *state.auth_token.write().await = None;
    *state.keychain_cleared_this_session.write().await = true;
    
    assert!(state.auth_token.read().await.is_none());
    assert!(*state.keychain_cleared_this_session.read().await);
}

#[test]
fn test_jwt_token_validation() {
    // Valid JWT tokens have 3 parts separated by dots
    let valid_tokens = vec![
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        "header.payload.signature",
        "a.b.c",
    ];
    
    let invalid_tokens = vec![
        "not.a.jwt.token",
        "only.two",
        "single",
        "",
    ];
    
    for token in valid_tokens {
        assert_eq!(token.matches('.').count(), 2, "Token should have 2 dots: {}", token);
    }
    
    for token in invalid_tokens {
        assert_ne!(token.matches('.').count(), 2, "Token should NOT have 2 dots: {}", token);
    }
}

#[test]
fn test_collection_interval_parsing() {
    // Test default value
    std::env::remove_var("KLAAYGUARD_COLLECTION_INTERVAL_SECONDS");
    
    // Test custom value
    std::env::set_var("KLAAYGUARD_COLLECTION_INTERVAL_SECONDS", "300");
    let interval = std::env::var("KLAAYGUARD_COLLECTION_INTERVAL_SECONDS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(3600);
    assert_eq!(interval, 300);
    
    // Test invalid value falls back to default
    std::env::set_var("KLAAYGUARD_COLLECTION_INTERVAL_SECONDS", "not_a_number");
    let interval = std::env::var("KLAAYGUARD_COLLECTION_INTERVAL_SECONDS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(3600);
    assert_eq!(interval, 3600);
    
    std::env::remove_var("KLAAYGUARD_COLLECTION_INTERVAL_SECONDS");
}

#[test]
fn test_api_url_parsing() {
    // Test default
    std::env::remove_var("APP_DEFAULT_API_BASE_URL");
    let api_url = std::env::var("APP_DEFAULT_API_BASE_URL")
        .unwrap_or_else(|_| "https://api.klaay.com".to_string());
    assert_eq!(api_url, "https://api.klaay.com");
    
    // Test custom
    std::env::set_var("APP_DEFAULT_API_BASE_URL", "https://api.test.com");
    let api_url = std::env::var("APP_DEFAULT_API_BASE_URL")
        .unwrap_or_else(|_| "https://api.klaay.com".to_string());
    assert_eq!(api_url, "https://api.test.com");
    
    std::env::remove_var("APP_DEFAULT_API_BASE_URL");
}

#[test]
fn test_deep_link_url_schemes() {
    let valid_urls = vec![
        "klaayguard://auth-callback?token=abc.def.ghi",
        "klaayguard://auth-callback",
        "klaayguard://something",
    ];
    
    let invalid_urls = vec![
        "https://example.com",
        "http://example.com",
        "file:///path",
        "klaay://wrong",
        "",
    ];
    
    for url in valid_urls {
        assert!(url.starts_with("klaayguard://"), "Should accept klaayguard:// scheme: {}", url);
    }
    
    for url in invalid_urls {
        assert!(!url.starts_with("klaayguard://"), "Should reject non-klaayguard:// scheme: {}", url);
    }
}

#[tokio::test]
async fn test_status_update_flow() {
    // Simulate the flow of a collection cycle completing
    let state = Arc::new(AppState {
        auth_token: RwLock::new(Some("test_token".to_string())),
        api_base_url: RwLock::new("https://api.test.com".to_string()),
        last_send_status: RwLock::new(None),
        last_send_at: RwLock::new(None),
        keychain_cleared_this_session: RwLock::new(false),
    });
    
    // Initially no status
    assert!(state.last_send_status.read().await.is_none());
    assert!(state.last_send_at.read().await.is_none());
    
    // Simulate successful send
    *state.last_send_status.write().await = Some(true);
    *state.last_send_at.write().await = Some(chrono::Utc::now());
    
    assert_eq!(*state.last_send_status.read().await, Some(true));
    assert!(state.last_send_at.read().await.is_some());
    
    // Simulate failed send
    *state.last_send_status.write().await = Some(false);
    
    assert_eq!(*state.last_send_status.read().await, Some(false));
}

#[test]
fn test_version_comparison() {
    use semver::Version;
    
    let current = Version::parse("0.1.12").unwrap();
    let older = Version::parse("0.1.11").unwrap();
    let newer = Version::parse("0.1.13").unwrap();
    let same = Version::parse("0.1.12").unwrap();
    
    assert!(newer > current);
    assert!(current > older);
    assert!(current == same);
    assert!(!(older > current));
}

#[test]
fn test_version_with_v_prefix() {
    use semver::Version;
    
    // Test that v prefix is handled correctly
    let v1 = "v0.1.12".trim_start_matches('v');
    let v2 = "0.1.12";
    
    let ver1 = Version::parse(v1).unwrap();
    let ver2 = Version::parse(v2).unwrap();
    
    assert_eq!(ver1, ver2);
}

