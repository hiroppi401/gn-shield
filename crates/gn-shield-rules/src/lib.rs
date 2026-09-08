//! Rule and signature matching engine for GN-Shield.
//! Integrates SHA-256 hash calculation, local hash reputation store, and YARA-X scanning.

use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// Standard EICAR Antivirus Test File rule string.
pub const EICAR_RULE: &str = r#"
rule EICAR_Test_File {
    meta:
        description = "Standard EICAR Antivirus Test Pattern"
        author = "GN-Shield"
        severity = "high"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
"#;

/// Standard EICAR test file payload bytes (without trailing newline).
pub const EICAR_PAYLOAD: &[u8] =
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

/// Computes SHA-256 hex string from byte buffer.
#[must_use]
pub fn calculate_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Computes SHA-256 hex string directly from file path using streaming buffer.
pub fn calculate_sha256_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hex::encode(hasher.finalize()))
}

/// Local Hash Reputation Store (Known-bad malware hashes).
#[derive(Debug, Default, Clone)]
pub struct HashReputationStore {
    known_bad: HashSet<String>,
}

impl HashReputationStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            known_bad: HashSet::new(),
        }
    }

    pub fn add_known_bad(&mut self, hash: &str) {
        self.known_bad.insert(hash.to_lowercase());
    }

    #[must_use]
    pub fn is_known_bad(&self, hash: &str) -> bool {
        self.known_bad.contains(&hash.to_lowercase())
    }
}

/// YARA-X Rules wrapper for GN-Shield.
pub struct YaraEngine {
    rules: yara_x::Rules,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScanResult {
    pub matched_rules: Vec<String>,
    pub static_score: f32,
}

impl YaraEngine {
    /// Compiles default rule set (including EICAR test rule).
    pub fn new_with_default_rules() -> Result<Self, String> {
        let mut compiler = yara_x::Compiler::new();
        compiler
            .add_source(EICAR_RULE)
            .map_err(|e| format!("Failed to compile default rules: {e}"))?;
        let rules = compiler.build();
        Ok(Self { rules })
    }

    /// Compiles custom rules from a YARA rule source string.
    pub fn from_source(source: &str) -> Result<Self, String> {
        let mut compiler = yara_x::Compiler::new();
        compiler
            .add_source(source)
            .map_err(|e| format!("Failed to compile custom rules: {e}"))?;
        let rules = compiler.build();
        Ok(Self { rules })
    }

    /// Scans a byte buffer and returns matched rules and a calculated static score.
    pub fn scan_bytes(&self, data: &[u8]) -> Result<ScanResult, String> {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        let scan_results = scanner
            .scan(data)
            .map_err(|e| format!("YARA-X scan error: {e}"))?;

        let mut matched_rules = Vec::new();
        for matching_rule in scan_results.matching_rules() {
            matched_rules.push(matching_rule.identifier().to_string());
        }

        let static_score = if matched_rules.is_empty() {
            0.0
        } else {
            // In default ruleset, any signature match is high severity (e.g. 1.0)
            1.0
        };

        Ok(ScanResult {
            matched_rules,
            static_score,
        })
    }

    /// Scans a file by reading its contents.
    pub fn scan_file(&self, path: &Path) -> Result<ScanResult, String> {
        let data = std::fs::read(path).map_err(|e| format!("Failed to read file {path:?}: {e}"))?;
        self.scan_bytes(&data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_sha256() {
        let data = b"GN-Shield Test Payload";
        let hash = calculate_sha256(data);
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_hash_reputation() {
        let mut store = HashReputationStore::new();
        let test_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        assert!(!store.is_known_bad(test_hash));

        store.add_known_bad(test_hash);
        assert!(store.is_known_bad(test_hash));
        assert!(store.is_known_bad(&test_hash.to_uppercase()));
    }

    #[test]
    fn test_eicar_detection() {
        let engine = YaraEngine::new_with_default_rules().expect("Engine creation failed");

        // Clean data should not trigger matches
        let clean = b"This is a legitimate clean text file for developer tools.";
        let res_clean = engine.scan_bytes(clean).expect("Scan failed");
        assert!(res_clean.matched_rules.is_empty());
        assert_eq!(res_clean.static_score, 0.0);

        // Standard EICAR payload must be detected
        let res_eicar = engine.scan_bytes(EICAR_PAYLOAD).expect("Scan failed");
        assert!(!res_eicar.matched_rules.is_empty());
        assert_eq!(res_eicar.matched_rules[0], "EICAR_Test_File");
        assert_eq!(res_eicar.static_score, 1.0);
    }
}
