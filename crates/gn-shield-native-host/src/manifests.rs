//! Host manifest generator and installation helpers for Chrome and Firefox native messaging.

use serde_json::json;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Fixed Chrome/Edge/Brave Extension ID derived from deterministic public key
pub const CHROME_EXTENSION_ID: &str = "acdgclnhgfblkcpbleihngdecipmalmb";

/// Fixed Firefox WebExtension ID
pub const FIREFOX_EXTENSION_ID: &str = "companion@gn-shield.org";

/// Native messaging host identifier registered in browsers
pub const NATIVE_HOST_NAME: &str = "com.gnshield.host";

/// Human-readable host description
pub const NATIVE_HOST_DESCRIPTION: &str = "GN-Shield Native Messaging Companion Host";

/// Generates the manifest JSON for Chromium-based browsers (Chrome, Edge, Brave).
#[must_use]
pub fn generate_chrome_manifest(binary_path: &Path) -> serde_json::Value {
    json!({
        "name": NATIVE_HOST_NAME,
        "description": NATIVE_HOST_DESCRIPTION,
        "path": binary_path.to_string_lossy(),
        "type": "stdio",
        "allowed_origins": [
            format!("chrome-extension://{CHROME_EXTENSION_ID}/")
        ]
    })
}

/// Generates the manifest JSON for Mozilla Firefox.
#[must_use]
pub fn generate_firefox_manifest(binary_path: &Path) -> serde_json::Value {
    json!({
        "name": NATIVE_HOST_NAME,
        "description": NATIVE_HOST_DESCRIPTION,
        "path": binary_path.to_string_lossy(),
        "type": "stdio",
        "allowed_extensions": [
            FIREFOX_EXTENSION_ID
        ]
    })
}

/// Returns the standard installation paths for native messaging manifests on Linux.
#[must_use]
pub fn standard_manifest_paths(system_wide: bool) -> (Vec<PathBuf>, Vec<PathBuf>) {
    if system_wide {
        let chrome_paths = vec![
            PathBuf::from("/etc/opt/chrome/native-messaging-hosts"),
            PathBuf::from("/etc/chromium/native-messaging-hosts"),
            PathBuf::from("/etc/opt/edge/native-messaging-hosts"),
        ];
        let firefox_paths = vec![
            PathBuf::from("/usr/lib/mozilla/native-messaging-hosts"),
            PathBuf::from("/usr/lib64/mozilla/native-messaging-hosts"),
        ];
        (chrome_paths, firefox_paths)
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let chrome_paths = vec![
            PathBuf::from(&home).join(".config/google-chrome/NativeMessagingHosts"),
            PathBuf::from(&home).join(".config/chromium/NativeMessagingHosts"),
            PathBuf::from(&home).join(".config/BraveSoftware/Brave-Browser/NativeMessagingHosts"),
        ];
        let firefox_paths = vec![PathBuf::from(&home).join(".mozilla/native-messaging-hosts")];
        (chrome_paths, firefox_paths)
    }
}

/// Installs the native host manifests to the specified target directories.
pub fn install_manifest_file(
    dir: &Path,
    manifest_content: &serde_json::Value,
) -> io::Result<PathBuf> {
    fs::create_dir_all(dir)?;
    let target_file = dir.join(format!("{NATIVE_HOST_NAME}.json"));
    let formatted = serde_json::to_string_pretty(manifest_content)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    fs::write(&target_file, formatted)?;
    Ok(target_file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_structure() {
        let bin = PathBuf::from("/usr/local/bin/gn-shield-native-host");

        let chrome_manifest = generate_chrome_manifest(&bin);
        assert_eq!(chrome_manifest["name"], NATIVE_HOST_NAME);
        assert_eq!(chrome_manifest["type"], "stdio");
        let origins = chrome_manifest["allowed_origins"]
            .as_array()
            .expect("origins array");
        assert_eq!(
            origins[0],
            format!("chrome-extension://{CHROME_EXTENSION_ID}/")
        );

        let ff_manifest = generate_firefox_manifest(&bin);
        assert_eq!(ff_manifest["name"], NATIVE_HOST_NAME);
        assert_eq!(ff_manifest["type"], "stdio");
        let extensions = ff_manifest["allowed_extensions"]
            .as_array()
            .expect("extensions array");
        assert_eq!(extensions[0], FIREFOX_EXTENSION_ID);
    }
}
