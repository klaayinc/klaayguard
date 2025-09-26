use semver::Version;

fn compare_versions(current: &str, release: &str) -> bool {
    // Normalize versions by removing 'v' prefix for comparison
    let normalized_current = current.trim_start_matches('v');
    let normalized_release = release.trim_start_matches('v');

    // Parse versions as semantic versions for proper comparison
    let current_semver = match Version::parse(normalized_current) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "❌ Failed to parse current version '{}': {}",
                normalized_current, e
            );
            return false;
        }
    };

    let release_semver = match Version::parse(normalized_release) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "❌ Failed to parse release version '{}': {}",
                normalized_release, e
            );
            return false;
        }
    };

    // Only suggest update if release version is newer
    release_semver > current_semver
}

fn main() {
    // Test the problematic case from the logs
    let current = "0.1.12";
    let release = "v0.1.11";

    println!("Testing version comparison:");
    println!("Current: {}", current);
    println!("Release: {}", release);

    let should_update = compare_versions(current, release);
    println!("Should update: {}", should_update);

    if should_update {
        println!("✅ Update available: {} -> {}", current, release);
    } else {
        println!(
            "✅ No update needed - current version {} is newer than or equal to release {}",
            current, release
        );
    }

    // Test a legitimate update case
    let current2 = "0.1.11";
    let release2 = "v0.1.12";

    println!("\nTesting legitimate update case:");
    println!("Current: {}", current2);
    println!("Release: {}", release2);

    let should_update2 = compare_versions(current2, release2);
    println!("Should update: {}", should_update2);

    if should_update2 {
        println!("✅ Update available: {} -> {}", current2, release2);
    } else {
        println!(
            "✅ No update needed - current version {} is newer than or equal to release {}",
            current2, release2
        );
    }
}
