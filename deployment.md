# Production Docker Deployment

This guide describes how to run `imap-cache-rs` in Docker for a production deployment.

The recommended production shape is:

- one Docker container for `imap-cache-rs`
- PostgreSQL as the canonical metadata store
- Redis for pub/sub, coordination, and short-lived cache/workers
- an external S3-compatible object store for raw message and MIME blobs
- TLS certificates mounted into the container for IMAP STARTTLS and implicit TLS

If you are using MinIO locally, treat that as a development or compatibility substitute, not as the production object store.

## Prerequisites

- Docker Engine or Docker Desktop
- Docker Compose v2
- An external S3-compatible bucket plus access keys
- A TLS certificate and private key for the IMAP endpoint
- A random `ENCRYPTION_MASTER_KEY` with at least 32 bytes of entropy

## Recommended Deployment Model

The release workflow publishes the Docker image to `ghcr.io/esaiaswestberg/imapped` with both the release tag and `latest`. Production Compose should pull `latest`; use a tag-specific image if you want to pin a deployment to a particular release.

You can still build a local image for development or custom deployment scenarios, but that is not required for the standard production path.

The application reads configuration from:

- `--config /path/to/config.toml`
- or `APP_CONFIG_PATH=/path/to/config.toml`
- or environment variables directly

Environment variables are usually simplest in Docker because they keep secrets out of the image.

## Example Environment File

Start from [`.env.example`](./.env.example) and create a production-specific file, for example `.env.production`.

At minimum, set:

- `APP_ENV=production`
- `APP_BASE_URL=https://mail.example.com`
- `ENCRYPTION_MASTER_KEY=<random-secret>`
- `DATABASE_URL=<production-postgres-url>`
- `REDIS_URL=<production-redis-url>`
- `R2_ENDPOINT=https://<account-id>.r2.cloudflarestorage.com` or another S3-compatible endpoint
- `R2_BUCKET=<bucket-name>`
- `R2_ACCESS_KEY_ID=<access-key>`
- `R2_SECRET_ACCESS_KEY=<secret-key>`
- `IMAP_TLS_CERT_PATH=/certs/imap.crt`
- `IMAP_TLS_KEY_PATH=/certs/imap.key`
- `OBJECT_STORE_PATH=/app/data/blob`
- `SEARCH_INDEX_PATH=/app/data/search`

For production, you should also consider enabling:

- `METRICS_BIND=0.0.0.0:9090` if you want a metrics endpoint
- `HTTP_BIND=0.0.0.0:8080` if you want admin/HTTP endpoints exposed on a dedicated port

## Example Compose File

The repository includes [`docker-compose.prod.yml`](./docker-compose.prod.yml). It pulls `ghcr.io/esaiaswestberg/imapped:latest`, provisions PostgreSQL and Redis locally, and leaves the object store external and S3-compatible.

Start it with:

```bash
docker compose -f docker-compose.prod.yml up -d
```

Run migrations with:

```bash
docker compose -f docker-compose.prod.yml run --rm imap-cache run-migrations
```

Bootstrap users and accounts with the same compose file:

```bash
docker compose -f docker-compose.prod.yml run --rm imap-cache create-user --username-email user@example.test --password 'change-me'
docker compose -f docker-compose.prod.yml run --rm imap-cache add-account \
  --user-email user@example.test \
  --display-name "Primary Mail" \
  --email-address user@example.test \
  --upstream-host imap.provider.example \
  --upstream-port 993 \
  --upstream-tls-mode tls \
  --upstream-auth-method login \
  --upstream-username user@example.test \
  --upstream-secret 'upstream-password'
```

Notes:

- The container listens on 1143 and 1993 internally by default. Port mapping exposes standard IMAP ports on the host.
- The data volume holds the search index and other runtime data. Keep it persistent.
- The compose file is intentionally small and expects the S3-compatible object store to be provided externally.

## Build The Image

This is optional and mainly useful for local testing or custom image inspection.

Build locally:

```bash
docker build -t imap-cache-rs:latest .
```

If you want to pin to a release tag or a custom registry, update the `image:` value in [`docker-compose.prod.yml`](./docker-compose.prod.yml) accordingly.

## Run Migrations

Before opening the service to clients, run the database migrations once:

```bash
docker compose -f docker-compose.prod.yml run --rm imap-cache run-migrations
```

That command uses the same environment and database connection string as the main service.

## Start The Service

```bash
docker compose -f docker-compose.prod.yml up -d
```

After startup, confirm:

- the IMAP listeners are reachable on the mapped ports
- PostgreSQL connectivity works
- Redis connectivity works
- the object storage endpoint, bucket, and credentials are correct

## Operational Notes

- Keep `ENCRYPTION_MASTER_KEY` stable across restarts.
- Back up PostgreSQL regularly. It is the canonical state for accounts, mailboxes, mappings, sync checkpoints, and mutation queues.
- Keep the external object store durable. Raw RFC822 blobs and MIME content rely on it.
- Monitor the HTTP metrics endpoint if you enable it.
- Prefer reverse proxy or firewall rules in front of any admin or HTTP endpoints.
- Expose only the ports you actually need.

## Production Checklist

- `APP_ENV=production`
- `DATABASE_URL` points to production PostgreSQL
- `REDIS_URL` points to production Redis
- S3-compatible object store endpoint, bucket, and credentials are valid
- TLS certificate and key are mounted read-only
- persistent volume exists for local cache and search index data
- migrations have been run successfully
- at least one administrative user has been created
- one or more upstream mail accounts have been added

When those items are in place, the container is ready for normal IMAP client traffic.
