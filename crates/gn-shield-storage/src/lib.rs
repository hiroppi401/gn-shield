//! Storage abstraction and embedded migrations for GN-Shield.

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug)]
pub struct StorageManager {
    pub schema_version: u32,
}

impl Default for StorageManager {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
        }
    }
}
