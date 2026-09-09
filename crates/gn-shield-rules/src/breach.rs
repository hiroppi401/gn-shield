//! Credential breach checker using k-anonymity scheme.
//!
//! Under k-anonymity, only the first 5 characters of a credential's hash are queried
//! (e.g., against Have I Been Pwned or a local range database). The remaining characters
//! and the raw password/credential NEVER leave the machine or enter external logs.

use sha1::{Digest, Sha1};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreachMatchResult {
    pub is_breached: bool,
    pub count: u64,
    pub prefix: String,
}

pub struct KAnonymityChecker;

impl KAnonymityChecker {
    /// Computes the 40-character uppercase hexadecimal SHA-1 hash of a credential,
    /// returning the 5-character prefix and the 35-character suffix.
    ///
    /// # Privacy Guarantee
    /// The raw credential is consumed within this function and never stored.
    #[must_use]
    pub fn split_sha1_hash(credential: &str) -> (String, String) {
        let mut hasher = Sha1::new();
        hasher.update(credential.as_bytes());
        let hash = hex::encode_upper(hasher.finalize());
        let prefix = hash[0..5].to_string();
        let suffix = hash[5..].to_string();
        (prefix, suffix)
    }

    /// Evaluates a multi-line range response against the local suffix.
    ///
    /// Each line of the range response has the format:
    /// `<SUFFIX>:<COUNT>`
    /// e.g. `0018A45C4D1787236E33B0CF63AB333AC10:2`
    #[must_use]
    pub fn evaluate_range_response(
        prefix: &str,
        local_suffix: &str,
        range_response: &str,
    ) -> BreachMatchResult {
        let normalized_suffix = local_suffix.trim().to_ascii_uppercase();

        for line in range_response.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if let Some((suffix, count_str)) = line.split_once(':') {
                if suffix.trim().eq_ignore_ascii_case(&normalized_suffix) {
                    let count = count_str.trim().parse::<u64>().unwrap_or(1);
                    return BreachMatchResult {
                        is_breached: true,
                        count,
                        prefix: prefix.to_string(),
                    };
                }
            }
        }

        BreachMatchResult {
            is_breached: false,
            count: 0,
            prefix: prefix.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_sha1_hash() {
        // "password" in SHA-1 is 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let (prefix, suffix) = KAnonymityChecker::split_sha1_hash("password");
        assert_eq!(prefix, "5BAA6");
        assert_eq!(suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
        assert_eq!(prefix.len(), 5);
        assert_eq!(suffix.len(), 35);
    }

    #[test]
    fn test_evaluate_range_response_match() {
        let (prefix, suffix) = KAnonymityChecker::split_sha1_hash("password");
        let mock_range = "0018A45C4D1787236E33B0CF63AB333AC10:3\n\
                          1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\n\
                          FE8A99C09944A9F24FE3487DE697B76D49F:1";

        let result = KAnonymityChecker::evaluate_range_response(&prefix, &suffix, mock_range);
        assert!(result.is_breached);
        assert_eq!(result.count, 3861493);
        assert_eq!(result.prefix, "5BAA6");
    }

    #[test]
    fn test_evaluate_range_response_no_match() {
        let (prefix, suffix) =
            KAnonymityChecker::split_sha1_hash("a_very_unique_unbreached_pass_9991283");
        let mock_range = "0018A45C4D1787236E33B0CF63AB333AC10:3\n\
                          FE8A99C09944A9F24FE3487DE697B76D49F:1";

        let result = KAnonymityChecker::evaluate_range_response(&prefix, &suffix, mock_range);
        assert!(!result.is_breached);
        assert_eq!(result.count, 0);
    }
}
