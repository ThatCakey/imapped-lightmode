# imap-cache-rs

`imap-cache-rs` is a Rust IMAP caching proxy and mirror service.

It exposes an IMAP server to downstream mail clients, mirrors upstream mailboxes into local storage, indexes message content for search, and keeps enough state in PostgreSQL to survive restarts and drive sync/mutation workflows.

## Current shape

This repository is currently organized as a single Rust crate with these major modules:

- `src/protocol/imap.rs` for IMAP command handling
- `src/upstream/` for the upstream IMAP client
- `src/sync/` for mailbox synchronization and mutation replay
- `src/db/` for PostgreSQL repositories and migrations
- `src/storage/` for object storage backends
- `src/search/` for Tantivy-backed search
- `src/admin.rs` for operational CLI commands

## Features implemented

- IMAP login, select, fetch, store, copy, move, expunge, append, idle, and related protocol plumbing
- PostgreSQL-backed metadata storage
- R2/S3-compatible object storage abstraction with filesystem and in-memory test backends
- Tantivy full-text indexing
- Redis-backed coordination and event fanout hooks
- Admin CLI for common operational tasks
- Integration and protocol tests

## Quick start

1. Start local dependencies.
2. Export configuration through environment variables or a config file.
3. Run the server or the admin CLI.

### Local development

```bash
make up
make test
```

To bring up the optional Dovecot upstream service for integration testing, use:

```bash
make up-test
```

### Admin commands

```bash
cargo run --bin imap-cache-rs -- --help
cargo run --bin imap-cache-rs -- list-accounts --user-email user@example.test
```

## Configuration

See [`config.example.toml`](./config.example.toml) for a baseline config file and [`docker-compose.yml`](./docker-compose.yml) for a local development stack.

## Testing

The test suite includes unit, integration, protocol, sync, storage, search, and live-upstream coverage.
Live upstream tests read credentials from `.testing-credentials` in the repo root and use the `IMAP (SSL/TLS)` endpoint plus the listed username/password.
If you prefer a containerized upstream instead, start the compose `test` profile and point the relevant tests at the exposed Dovecot ports.

```bash
cargo test
```
