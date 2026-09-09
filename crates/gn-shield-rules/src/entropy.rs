//! Shannon entropy calculation and entropy shift detection.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// Computes Shannon entropy of a byte slice in bits per byte (range: [0.0, 8.0]).
/// High entropy (~7.5 - 8.0) is a primary indicator of encrypted or compressed content.
#[must_use]
pub fn shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let len = data.len() as f32;
    let mut entropy = 0.0f32;

    for &count in &counts {
        if count > 0 {
            let p = (count as f32) / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Calculates Shannon entropy of a file, sampling up to 64 KB to keep resource footprint minimal.
pub fn calculate_file_entropy(path: &Path) -> io::Result<f32> {
    let mut file = File::open(path)?;
    let mut buffer = [0u8; 65536]; // 64 KB sample
    let bytes_read = file.read(&mut buffer)?;
    if bytes_read == 0 {
        return Ok(0.0);
    }
    Ok(shannon_entropy(&buffer[..bytes_read]))
}

/// Checks if data entropy exceeds the given threshold (default typically >= 7.2).
#[must_use]
pub fn is_high_entropy(data: &[u8], threshold: f32) -> bool {
    shannon_entropy(data) >= threshold
}

/// Checks if an entropy shift is significant (e.g. from plaintext to ciphertext).
#[must_use]
pub fn is_significant_entropy_shift(
    baseline_entropy: f32,
    new_entropy: f32,
    min_increase: f32,
) -> bool {
    new_entropy > baseline_entropy && (new_entropy - baseline_entropy) >= min_increase
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy_all_zeros() {
        let data = vec![0u8; 1000];
        assert_eq!(shannon_entropy(&data), 0.0);
    }

    #[test]
    fn test_shannon_entropy_plaintext() {
        let text = b"This is normal plaintext ASCII source code with repeated letters and spaces.";
        let entropy = shannon_entropy(text);
        assert!(
            entropy > 3.0 && entropy < 5.0,
            "Plaintext entropy: {entropy}"
        );
        assert!(!is_high_entropy(text, 7.2));
    }

    #[test]
    fn test_shannon_entropy_pseudo_random_encrypted() {
        // High-entropy simulated encrypted payload with uniform byte distribution
        let mut pseudo_random = Vec::with_capacity(256 * 10);
        for _ in 0..10 {
            for b in 0..=255u8 {
                pseudo_random.push(b);
            }
        }
        let entropy = shannon_entropy(&pseudo_random);
        assert!(entropy > 7.9, "Random byte entropy: {entropy}");
        assert!(is_high_entropy(&pseudo_random, 7.2));
        assert!(is_significant_entropy_shift(4.0, entropy, 2.5));
    }
}
