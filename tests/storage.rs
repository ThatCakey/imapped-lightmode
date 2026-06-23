use imap_cache_rs::storage::{
    ObjectStore, ObjectType, content_addressed_key, memory::MemoryObjectStore,
    validate_content_addressed_bytes,
};
use tempfile::tempdir;

#[tokio::test]
async fn content_addressed_keys_are_deterministic() {
    let key_a = content_addressed_key(ObjectType::Rfc822, b"hello");
    let key_b = content_addressed_key(ObjectType::Rfc822, b"hello");
    let key_c = content_addressed_key(ObjectType::Rfc822, b"world");

    assert_eq!(key_a, key_b);
    assert_ne!(key_a, key_c);
}

#[tokio::test]
async fn memory_store_round_trips_blobs() {
    let store = MemoryObjectStore::new();
    let key = content_addressed_key(ObjectType::Rfc822, b"message");
    let meta = store.put(&key, b"message").await.unwrap();
    assert!(store.exists(&key).await.unwrap());
    assert_eq!(store.get(&key).await.unwrap().unwrap(), b"message");
    assert_eq!(
        store.get_range(&key, 1, Some(4)).await.unwrap().unwrap(),
        b"ess"
    );
    assert_eq!(meta.size_octets, 7);
    store.delete(&key).await.unwrap();
    assert!(!store.exists(&key).await.unwrap());
}

#[tokio::test]
async fn memory_store_rejects_mismatched_content() {
    let store = MemoryObjectStore::new();
    let key = content_addressed_key(ObjectType::Rfc822, b"message");
    let err = store.put(&key, b"different").await.unwrap_err();
    assert!(err.to_string().contains("content hash mismatch"));
}

#[tokio::test]
async fn filesystem_store_validates_bytes_on_read_and_write() {
    let dir = tempdir().unwrap();
    let store = imap_cache_rs::storage::filesystem::FilesystemObjectStore::new(dir.path());
    let key = content_addressed_key(ObjectType::Rfc822, b"message");

    store.put(&key, b"message").await.unwrap();
    assert_eq!(store.get(&key).await.unwrap().unwrap(), b"message");

    std::fs::write(dir.path().join(&key), b"corrupted").unwrap();
    let err = store.get(&key).await.unwrap_err();
    assert!(err.to_string().contains("content hash mismatch"));
}

#[test]
fn content_addressed_bytes_are_validated_against_keys() {
    let key = content_addressed_key(ObjectType::Rfc822, b"message");
    validate_content_addressed_bytes(&key, b"message").unwrap();

    let err = validate_content_addressed_bytes(&key, b"different").unwrap_err();
    assert!(err.to_string().contains("content hash mismatch"));
}
