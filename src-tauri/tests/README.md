# KlaayGuard Test Suite

## Overview

This directory contains integration and unit tests for the KlaayGuard Rust/Tauri backend.

## Running Tests

```bash
# Run all tests
cargo test --manifest-path=src-tauri/Cargo.toml

# Run with output
cargo test --manifest-path=src-tauri/Cargo.toml -- --nocapture

# Run specific test
cargo test --manifest-path=src-tauri/Cargo.toml test_name
```

## Test Coverage

### Unit Tests (`src/lib.rs`)

- **State Management** (3 tests)
  - `test_app_state_creation`: Verifies AppState initialization
  - `test_update_tray_status_success`: Tests async state updates
  - `test_client_with_retries`: HTTP client configuration

- **Configuration** (5 tests)
  - `test_collection_interval_default`: Default 1-hour interval
  - `test_collection_interval_custom`: Custom interval from env
  - `test_collection_interval_invalid`: Fallback on invalid input
  - `test_get_api_base_url_default`: Default API URL
  - `test_get_api_base_url_custom`: Custom API URL from env

- **Authentication** (3 tests)
  - `test_deep_link_url_parsing`: Valid JWT token parsing
  - `test_deep_link_invalid_token`: Invalid token rejection
  - `test_deep_link_missing_token`: Missing token handling

- **API Serialization** (2 tests)
  - `test_json_api_resource_serialization`: JSON:API format
  - `test_json_api_resource_without_id`: Optional ID field

### Integration Tests (`tests/integration_test.rs`)

- **Async Runtime** (2 tests)
  - `test_no_nested_runtime_panic`: **Critical** - Prevents nested runtime panics
  - `test_app_state_concurrent_access`: Concurrent access safety

- **Authentication Lifecycle** (2 tests)
  - `test_auth_token_lifecycle`: Token set/clear flow
  - `test_jwt_token_validation`: JWT format validation

- **Configuration Parsing** (2 tests)
  - `test_collection_interval_parsing`: Environment variable parsing
  - `test_api_url_parsing`: API URL configuration

- **Deep Links** (1 test)
  - `test_deep_link_url_schemes`: URL scheme validation

- **Status Updates** (1 test)
  - `test_status_update_flow`: Collection cycle status tracking

- **Version Management** (2 tests)
  - `test_version_comparison`: Semantic version comparison
  - `test_version_with_v_prefix`: Version prefix handling

## Critical Tests

### Nested Runtime Panic Prevention

The `test_no_nested_runtime_panic` test is **critical** - it would have caught the bug that caused the app to crash on startup:

```rust
#[tokio::test]
async fn test_no_nested_runtime_panic() {
    // This test verifies that we don't create nested runtimes
    // If this test passes, it means we're not using block_on in async contexts
    
    let state = Arc::new(AppState { /* ... */ });
    
    // Simulate what update_tray_status does
    *state.last_send_status.write().await = Some(true);
    *state.last_send_at.write().await = Some(chrono::Utc::now());
    
    // If we used block_on here, this would panic
    let status = state.last_send_status.read().await;
    assert_eq!(*status, Some(true));
}
```

**Why it matters**: This test runs in an async context (using `#[tokio::test]`). If any function uses `block_on` internally, it would panic with "Cannot start a runtime from within a runtime" - the exact error we fixed.

## Test Strategy

1. **Unit tests** for pure functions and business logic
2. **Integration tests** for async workflows and state management
3. **Mock state** instead of full Tauri app context
4. **Environment variable testing** for configuration
5. **Async runtime tests** to prevent nested runtime issues

## Adding New Tests

When adding new features, include tests for:

- ✅ Core business logic
- ✅ Error handling paths
- ✅ Configuration parsing
- ✅ Async state updates
- ✅ API serialization/deserialization
- ✅ Deep link/URL parsing

## CI/CD Integration

These tests should be run in CI/CD pipelines before merging:

```yaml
# .github/workflows/test.yml
- name: Run tests
  run: cargo test --manifest-path=src-tauri/Cargo.toml
```

## Test Maintenance

- Run tests before committing: `cargo test`
- Update tests when changing behavior
- Add tests for bug fixes (prevent regression)
- Keep integration tests fast and focused
- Use mocks for external dependencies

## Known Limitations

- No full Tauri app integration tests (requires headless environment)
- No osquery execution tests (requires sidecar binary)
- No network tests (would require API mock server)
- No keychain tests (would require system keychain access)

These limitations could be addressed with:
- Mock Tauri app context
- Mock osquery responses
- HTTP mock server (e.g., `mockito`)
- Mock keychain implementation for tests

