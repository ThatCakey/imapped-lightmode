# imap-cache-rs

`imap-cache-rs` is a Rust IMAP caching proxy and mirror service.

It sits between downstream mail clients and one or more upstream IMAP servers. The server mirrors mailboxes into local storage, serves cached bodies and metadata locally, indexes parsed message content for search, and pushes local mutations back upstream when required.

## What It Includes

- A Tokio-based IMAP frontend with stateful command handling.
- An upstream IMAP client with TLS, STARTTLS, and capability detection.
- A sync engine that mirrors messages, reconciles flags, and replays queued mutations.
- PostgreSQL-backed canonical metadata and sync state.
- External S3-compatible object storage support, plus filesystem and in-memory backends for development and tests.
- Tantivy-backed full-text search.
- Redis-backed coordination and event fanout hooks.
- Admin CLI commands for user, account, sync, and cache management.
- A broad test suite covering protocol, sync, storage, search, metrics, and live-upstream behavior.

## Repository Layout

This repository is a Rust workspace. The main pieces are:

- `crates/core/` for shared domain types, errors, and security helpers.
- `crates/config/` for configuration loading.
- `crates/auth/` for authentication and account bootstrap logic.
- `crates/db/` for SQLx repositories and migrations.
- `crates/imap-server/` for the IMAP frontend and HTTP metrics/admin endpoints.
- `crates/upstream/` for the upstream IMAP client.
- `crates/sync/` for mailbox synchronization and mutation replay.
- `crates/storage/` for object storage abstractions and backends.
- `crates/search/` for Tantivy indexing and search.
- `crates/notifications/` for mailbox events and Redis relay hooks.
- `crates/test-support/` for shared live-test helpers.
- `src/` for the top-level binary and admin wiring.

## Status

The current implementation covers the core production path:

- IMAP login, capability negotiation, select/examine, fetch, store, copy, move, append, expunge, idle, namespace, enable, condstore, esearch, sort, and thread-related flows.
- Mailbox sync against upstream servers.
- Local storage of message blobs and parsed MIME data.
- Search and admin operations.

The codebase is already split into focused crates, so the architecture matches the eventual production deployment boundaries.

## Local Development

The repository includes a Docker-based local stack with PostgreSQL, Redis, MinIO-compatible storage, and an optional Dovecot upstream for integration tests.

```bash
make up
```

Run tests:

```bash
make test
```

Bring up the optional test upstream:

```bash
make up-test
```

Shut the stack down:

```bash
make down
```

## Production Docker Deployment

See [Production Docker Deployment](./deployment.md) for the recommended production setup, including:

- Building or pulling the service image.
- Running the app in Docker with persistent volumes via [`docker-compose.prod.yml`](./docker-compose.prod.yml).
- Bundling PostgreSQL and Redis in Compose while pointing the app at an external S3-compatible object store.
- Mounting TLS certificates for IMAP STARTTLS and implicit TLS.
- Running migrations before opening the service to clients.
- Bootstrapping users and mail accounts with the admin CLI.

## Configuration

Configuration can be supplied either through environment variables or a TOML file.

- Use `--config /path/to/config.toml` to point the binary at a config file.
- Alternatively set `APP_CONFIG_PATH=/path/to/config.toml`.
- See [`config.example.toml`](./config.example.toml) for a config-file example.
- See [`.env.example`](./.env.example) for an environment-variable example.

The important runtime settings include:

- listener bind addresses for IMAP, HTTP, and metrics
- `DATABASE_URL` for PostgreSQL
- `REDIS_URL` for Redis fanout and coordination
- `R2_*` values for the external S3-compatible object store endpoint and credentials
- `IMAP_TLS_CERT_PATH` and `IMAP_TLS_KEY_PATH` for TLS
- `ENCRYPTION_MASTER_KEY` for secret handling

## Administration

The binary exposes admin subcommands for common operational tasks.

Examples:

```bash
cargo run --bin imap-cache-rs -- --help
cargo run --bin imap-cache-rs -- run-migrations
cargo run --bin imap-cache-rs -- list-accounts --user-email user@example.test
```

## Testing

The test suite includes unit, integration, protocol, sync, storage, search, metrics, and live-upstream coverage.

Live upstream tests read credentials from `.testing-credentials` in the repository root and use the listed IMAP SSL/TLS endpoint plus username/password. Those tests are serialized with a shared file lock so they can run safely across multiple cargo test binaries.

Run the full suite with:

```bash
cargo test
```
