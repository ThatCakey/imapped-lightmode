BEGIN;

ALTER TABLE cache_objects
    DROP CONSTRAINT IF EXISTS cache_objects_object_type_blob_key_key;

DROP INDEX IF EXISTS cache_objects_object_type_blob_key_key;

CREATE UNIQUE INDEX IF NOT EXISTS cache_objects_account_object_type_blob_key_key
    ON cache_objects(account_id, object_type, blob_key);

COMMIT;
