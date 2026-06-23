# Architecture

`imap-cache-rs` is a production-shaped IMAP mirror built as a Rust workspace with clear boundaries between protocol handling, upstream access, sync, storage, search, coordination, and admin workflows.

## High-Level Flow

1. A mail client connects to the IMAP frontend.
2. The frontend authenticates the session and routes commands through repository-backed state.
3. Reads are served from PostgreSQL metadata and cached object storage where possible.
4. Cache misses and sync gaps are filled from the upstream IMAP server.
5. Mutations are written locally first, then replayed upstream through the mutation queue.
6. Redis and the in-process event hub fan mailbox changes out to active sessions and background workers.

## Workspace Layout

The repository is organized as a Rust workspace so the production boundaries are visible in code:

- `crates/imap-server/` owns the IMAP frontend and HTTP endpoints.
- `crates/upstream/` owns the upstream IMAP client.
- `crates/sync/` owns mailbox synchronization, checkpointing, and mutation replay.
- `crates/db/` owns SQLx repositories and schema migrations.
- `crates/storage/` owns R2/S3, filesystem, and memory object stores.
- `crates/search/` owns Tantivy indexing and search.
- `crates/auth/` owns local authentication and account bootstrap logic.
- `crates/notifications/` owns mailbox events and Redis relay hooks.
- `crates/core/` carries shared domain types, errors, and security helpers.
- `crates/config/` owns configuration loading.
- `crates/test-support/` holds live-test helpers and credentials parsing.

## Runtime Topology

The service can be deployed in two common shapes:

- Local development: Docker Compose with PostgreSQL, Redis, MinIO-compatible object storage, and optionally Dovecot as the upstream IMAP server.
- Production: Docker Compose with the app, PostgreSQL, and Redis services, plus an external S3-compatible object store and mounted TLS certificates.

The code paths are the same in both cases. Only the backing services change.

## Storage Model

- PostgreSQL stores canonical metadata, mailbox state, sync checkpoints, pending mutations, quotas, and audit records.
- Object storage stores raw RFC822 blobs, MIME body blobs, attachment data, and other large cached objects.
- Tantivy stores searchable content derived from parsed MIME bodies and headers.
- Redis supports pub/sub fanout, worker coordination, and short-lived shared state.

## Protocol Layer

The IMAP frontend keeps the server stateful and explicit:

- `NotAuthenticated`
- `Authenticated`
- `SelectedMailbox`
- `Logout`

It emits tagged and untagged responses directly and only advertises capabilities that are implemented.

## Sync Strategy

- Initial sync discovers mailboxes and ingests messages.
- Incremental sync uses mailbox checkpoints and upstream UID tracking.
- Flags are reconciled against upstream state so local metadata stays accurate.
- Pending mutations are replayed upstream with idempotency and backoff.
- UIDVALIDITY changes trigger local mailbox reset for the affected mailbox.

## Deployment Notes

The production Docker deployment should keep these boundaries in mind:

- PostgreSQL is the source of truth for metadata and sync state.
- An external durable S3-compatible object store holds the blob data.
- Redis is shared state for coordination and fanout, not a replacement for PostgreSQL.
- TLS material should be mounted into the container rather than baked into the image.

## Notes

The current repository already reflects the intended long-term structure instead of a single monolith. If the project is split further later, the current module boundaries should carry over with minimal behavioral change.
