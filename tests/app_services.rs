use imap_cache_rs::{
    AppServices,
    config::Config,
    storage::{ObjectType, content_addressed_key},
};
use tempfile::tempdir;

#[tokio::test]
async fn app_services_builds_filesystem_object_store() -> anyhow::Result<()> {
    let blob_dir = tempdir()?;
    let search_dir = tempdir()?;

    let mut config = Config::default();
    config.object_store_path = Some(blob_dir.path().join("objects"));
    config.search_index_path = Some(search_dir.path().join("index"));
    config.database_url = None;

    let services = AppServices::new(&config).await?;
    assert!(services.repository.is_none());
    assert!(services.sync_engine.is_none());

    let key = content_addressed_key(ObjectType::Rfc822, b"app-services");
    services.object_store.put(&key, b"app-services").await?;
    assert!(services.object_store.exists(&key).await?);
    assert_eq!(
        services.object_store.get(&key).await?.as_deref(),
        Some(&b"app-services"[..])
    );

    Ok(())
}
