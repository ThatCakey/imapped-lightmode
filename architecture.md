# Architecture

`imap-cache-rs` is designed as a production-shaped IMAP mirror with clear boundaries between protocol handling, sync, storage, and admin workflows.

## High-level flow

1. A mail client connects to the IMAP frontend.
2. The frontend authenticates the session and routes commands to repository-backed state.
3. Reads are served from PostgreSQL metadata and object storage.
4. Cache misses or first-sync gaps are filled from the upstream IMAP server.
5. Mutations are written locally first, then replayed upstream through the mutation queue.
6. Redis and the in-process event hub fan mailbox changes out to active sessions.

## Module boundaries

- `protocol` parses IMAP commands and renders IMAP responses.
- `upstream` speaks to the upstream IMAP provider.
- `sync` ingests messages, maintains checkpoints, and applies queued mutations.
- `db` owns SQLx repositories and schema migrations.
- `storage` abstracts R2/S3, filesystem, and memory object stores.
- `search` wraps Tantivy indexing and search.
- `auth` handles local authentication and account bootstrapping.
- `admin` exposes the operational CLI.

## Current storage model

- PostgreSQL stores canonical metadata and sync state.
- Object storage stores raw RFC822 messages and other large blobs.
- Tantivy stores searchable text derived from parsed MIME content.

## Notes

The repository is still a single-crate implementation. The long-term target in the objective is a multi-crate workspace, but the code already keeps the conceptual boundaries above so it can be split later without changing core behavior.

