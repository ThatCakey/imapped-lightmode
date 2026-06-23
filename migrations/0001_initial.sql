BEGIN;

CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username_email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    disabled_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS mail_accounts (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    display_name TEXT NOT NULL DEFAULT '',
    email_address TEXT NOT NULL,
    upstream_host TEXT NOT NULL,
    upstream_port INTEGER NOT NULL,
    upstream_tls_mode TEXT NOT NULL,
    upstream_auth_method TEXT NOT NULL,
    encrypted_upstream_username BYTEA NOT NULL,
    encrypted_upstream_secret BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    disabled_at TIMESTAMPTZ,
    last_sync_at TIMESTAMPTZ,
    last_sync_error TEXT
);

CREATE TABLE IF NOT EXISTS mailboxes (
    id BIGSERIAL PRIMARY KEY,
    account_id BIGINT NOT NULL REFERENCES mail_accounts(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    canonical_name TEXT NOT NULL,
    delimiter TEXT,
    attributes TEXT[] NOT NULL DEFAULT '{}',
    subscribed BOOLEAN NOT NULL DEFAULT FALSE,
    special_use TEXT,
    uidvalidity BIGINT,
    uidnext BIGINT,
    highestmodseq BIGINT,
    exists_count BIGINT NOT NULL DEFAULT 0,
    recent_count BIGINT NOT NULL DEFAULT 0,
    unseen_count BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(account_id, canonical_name)
);

CREATE TABLE IF NOT EXISTS messages (
    id BIGSERIAL PRIMARY KEY,
    account_id BIGINT NOT NULL REFERENCES mail_accounts(id) ON DELETE CASCADE,
    rfc822_blob_key TEXT NOT NULL,
    rfc822_sha256 TEXT NOT NULL,
    message_id_header TEXT,
    subject TEXT,
    from_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    to_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    cc_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    bcc_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    reply_to_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    envelope_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    bodystructure_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    internal_date TIMESTAMPTZ,
    sent_date TIMESTAMPTZ,
    size_octets BIGINT NOT NULL DEFAULT 0,
    text_preview TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS mailbox_messages (
    id BIGSERIAL PRIMARY KEY,
    mailbox_id BIGINT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    message_id BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    local_uid BIGINT NOT NULL,
    upstream_uid BIGINT,
    modseq BIGINT,
    flags TEXT[] NOT NULL DEFAULT '{}',
    keywords TEXT[] NOT NULL DEFAULT '{}',
    is_expunged BOOLEAN NOT NULL DEFAULT FALSE,
    expunged_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(mailbox_id, local_uid)
);
CREATE UNIQUE INDEX IF NOT EXISTS mailbox_messages_mailbox_upstream_uid_idx
    ON mailbox_messages(mailbox_id, upstream_uid)
    WHERE upstream_uid IS NOT NULL;

CREATE TABLE IF NOT EXISTS mime_parts (
    id BIGSERIAL PRIMARY KEY,
    message_id BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    part_path TEXT NOT NULL,
    content_type TEXT NOT NULL,
    charset TEXT,
    disposition TEXT,
    filename TEXT,
    content_id TEXT,
    size_octets BIGINT NOT NULL DEFAULT 0,
    blob_key TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    transfer_encoding TEXT,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS uid_mappings (
    id BIGSERIAL PRIMARY KEY,
    mailbox_id BIGINT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    local_uid BIGINT NOT NULL,
    upstream_uid BIGINT NOT NULL,
    upstream_uidvalidity BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(mailbox_id, local_uid),
    UNIQUE(mailbox_id, upstream_uid)
);

CREATE TABLE IF NOT EXISTS sync_state (
    id BIGSERIAL PRIMARY KEY,
    account_id BIGINT NOT NULL REFERENCES mail_accounts(id) ON DELETE CASCADE,
    mailbox_id BIGINT REFERENCES mailboxes(id) ON DELETE CASCADE,
    state_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_success_at TIMESTAMPTZ,
    last_attempt_at TIMESTAMPTZ,
    last_error TEXT
);

CREATE TABLE IF NOT EXISTS pending_mutations (
    id BIGSERIAL PRIMARY KEY,
    account_id BIGINT NOT NULL REFERENCES mail_accounts(id) ON DELETE CASCADE,
    mailbox_id BIGINT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    message_id BIGINT REFERENCES messages(id) ON DELETE SET NULL,
    mutation_type TEXT NOT NULL,
    payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ,
    idempotency_key TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sessions (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    account_id BIGINT REFERENCES mail_accounts(id) ON DELETE CASCADE,
    connection_id UUID NOT NULL UNIQUE,
    remote_addr TEXT,
    authenticated_at TIMESTAMPTZ,
    disconnected_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    account_id BIGINT REFERENCES mail_accounts(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cache_objects (
    id BIGSERIAL PRIMARY KEY,
    account_id BIGINT REFERENCES mail_accounts(id) ON DELETE CASCADE,
    object_type TEXT NOT NULL,
    blob_key TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_octets BIGINT NOT NULL DEFAULT 0,
    ref_count BIGINT NOT NULL DEFAULT 0,
    last_accessed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(object_type, blob_key)
);

CREATE TABLE IF NOT EXISTS quotas (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
    account_id BIGINT REFERENCES mail_accounts(id) ON DELETE CASCADE,
    max_bytes BIGINT NOT NULL,
    used_bytes BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK ((user_id IS NOT NULL)::int + (account_id IS NOT NULL)::int = 1)
);

CREATE INDEX IF NOT EXISTS mail_accounts_user_id_idx ON mail_accounts(user_id);
CREATE INDEX IF NOT EXISTS mailboxes_account_id_idx ON mailboxes(account_id);
CREATE INDEX IF NOT EXISTS messages_account_id_idx ON messages(account_id);
CREATE INDEX IF NOT EXISTS mailbox_messages_mailbox_id_idx ON mailbox_messages(mailbox_id);
CREATE INDEX IF NOT EXISTS sync_state_account_mailbox_idx ON sync_state(account_id, mailbox_id);
CREATE INDEX IF NOT EXISTS pending_mutations_account_status_idx ON pending_mutations(account_id, status, next_attempt_at);
CREATE INDEX IF NOT EXISTS audit_log_account_created_at_idx ON audit_log(account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS cache_objects_account_blob_key_idx ON cache_objects(account_id, blob_key);

COMMIT;
