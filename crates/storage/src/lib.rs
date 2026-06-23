pub mod filesystem;
pub mod memory;
pub mod r2;

pub use imap_cache_core::error::{Error, Result};
pub use imap_cache_core::storage::{
    ObjectMetadata, ObjectStore, ObjectType, content_addressed_key, validate_content_addressed_bytes,
    validate_object_key,
};
