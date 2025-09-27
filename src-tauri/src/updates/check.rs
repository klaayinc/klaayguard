use crate::updates::adapters::UpdateHttpClient;
use crate::updates::types::UpdateError;

#[derive(serde::Deserialize)]
struct ReleaseAsset {
    id: u64,
    name: String,
    #[serde(rename = "original_name")]
    _original_name: Option<String>,
}

#[derive(serde::Deserialize)]
struct ReleaseInfo {
    #[allow(dead_code)]
    #[serde(rename = "name")]
    _name: Option<String>,
    version: String,
    assets: Vec<ReleaseAsset>,
}

pub async fn check(
    api_base: &str,
    client: &impl UpdateHttpClient,
) -> Result<Option<String>, UpdateError> {
    let current_version = env!("CARGO_PKG_VERSION");
    log::info!(
        "🔍 Starting update check - current version: {}",
        current_version
    );
    let url = format!("{}/klaayguard/updates/latest", api_base);
    log::info!("🌐 Checking for updates from API: {}", url);

    let release: ReleaseInfo = client.get_json_blocking(&url)?;
    log::info!(
        "📦 Found release: {} with {} assets",
        release.version,
        release.assets.len()
    );

    let normalized_current = current_version.trim_start_matches('v');
    let normalized_release = release.version.trim_start_matches('v');
    let current_semver = semver::Version::parse(normalized_current)
        .map_err(|_| UpdateError::VersionParse(normalized_current.to_string()))?;
    let release_semver = semver::Version::parse(normalized_release)
        .map_err(|_| UpdateError::VersionParse(normalized_release.to_string()))?;

    if release_semver > current_semver {
        if let Some(dmg_asset) = release
            .assets
            .iter()
            .find(|a| a.name.ends_with(".dmg") || a.name.contains("MacOS"))
        {
            log::info!(
                "✅ Found DMG asset: {} (ID: {}) for update {} -> {}",
                dmg_asset.name,
                dmg_asset.id,
                current_version,
                release.version
            );
            return Ok(Some(dmg_asset.id.to_string()));
        } else {
            log::warn!("⚠️  No DMG asset found in release assets");
        }
    } else if release_semver < current_semver {
        log::info!(
            "✅ No update needed - current version {} is newer than release {}",
            current_version,
            release.version
        );
    } else {
        log::info!(
            "✅ No update needed - already at latest version: {}",
            current_version
        );
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::DeserializeOwned;

    struct FakeClient {
        json: String,
    }
    impl UpdateHttpClient for FakeClient {
        fn get_json_blocking<T: DeserializeOwned>(&self, _url: &str) -> Result<T, UpdateError> {
            serde_json::from_str(&self.json)
                .map_err(|e| UpdateError::InvalidResponse(e.to_string()))
        }
        fn get_bytes_blocking(&self, _url: &str) -> Result<Vec<u8>, UpdateError> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn returns_none_when_equal_version() {
        let body = serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "assets": []
        })
        .to_string();
        let fc = FakeClient { json: body };
        let res = check("http://x", &fc).await.unwrap();
        assert!(res.is_none());
    }

    #[tokio::test]
    async fn returns_asset_id_when_newer_with_dmg() {
        let body = serde_json::json!({
            "version": "9.9.9",
            "assets": [{"id": 42, "name": "KlaayGuard.dmg", "original_name": null}]
        })
        .to_string();
        let fc = FakeClient { json: body };
        let res = check("http://x", &fc).await.unwrap();
        assert_eq!(res, Some("42".to_string()));
    }
}
