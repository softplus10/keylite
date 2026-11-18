# Keylite

Keylite is an experimental Rust service for synchronizing opaque encrypted vault files, including KDBX. The server does not open, parse, or decrypt vault contents.

**Project status:** native Rust, scratch-container, Workers WebAssembly, local D1, CAS and multi-megabyte upload tests pass in GitHub Actions. Live Cloudflare deployment and GHCR publication have not been independently verified. Keep independent backups of vault files.

## Architecture

- `keylite-core`: portable BLAKE3 hashing, CAS preconditions, version DTOs.
- `keylite-native`: Axum HTTP API, SQLite persistence, Argon2id authentication.
- `migrations`: SQLite-compatible schema.
- `crates/worker`: Cloudflare Workers and D1 REST API implementation.

The native server is intended to run as one small executable on Linux, OpenBSD, or similar systems. The cloud implementation uses workers-rs and D1 while sharing the protocol and core crate.

## Quick start

```sh
cargo test --workspace
KEYLITE_LISTEN=127.0.0.1:8787 KEYLITE_DB=./keylite.sqlite cargo run -p keylite-native
```

The service initializes its database on startup. Bind only to localhost unless protected by TLS and authentication-aware reverse proxy configuration.

## API

All endpoints are prefixed with `/api`. After login, send `Authorization: Bearer <token>`.

| Method | Path | Description |
| --- | --- | --- |
| POST | /api/register | Create account with JSON email/password |
| POST | /api/login | Return a bearer token |
| POST | /api/logout | Revoke the bearer token |
| GET | /api/vaults | List vault metadata |
| POST | /api/vaults | Create an empty vault with JSON `{"name":"personal"}` |
| GET | /api/vaults/:id | Download current opaque bytes and ETag |
| GET | /api/vaults/:id/history | List the newest five versions |
| GET | /api/vaults/:id/history/:revision | Download an earlier version |
| PUT | /api/vaults/:id | Upload raw bytes with `If-Match` |
| DELETE | /api/vaults/:id | Delete a vault and its versions |

`If-Match: "*"` is accepted only for the first upload to an empty vault. Subsequent PUT requests must send the exact quoted ETag from GET or the previous successful PUT. Mismatches receive 412 Precondition Failed and a JSON response containing the current HEAD. Native writes use one SQLite transaction; D1 commits use a transactional SQL batch and trigger.

The server stores at most five revisions per vault. Each revision has a monotonically increasing number and a BLAKE3-256 content hash. If two different uploads have identical bytes, the second can still create a revision; comparison is against the observed HEAD, not just the new content hash.

## Limits and security

- Maximum vault size is 8 MiB for both servers. D1 supports this within its 2 MB per-value limit; 512 KiB chunks are stored in a separate table.
- Authentication passwords are hashed with Argon2id; the KDBX master password remains exclusively with the client.
- Bearer tokens expire after 24 hours and only token hashes are stored.
- TLS, registration throttling, email verification, monitoring, and backup procedures are required before public deployment.
- Conflict *detection* is supported, not automatic KDBX merging.
- No server-side protection against a malicious server presenting an older HEAD is claimed.

## Quotas

The environment variables KEYLITE_MAX_USERS and KEYLITE_MAX_VAULTS_PER_USER must be non-negative integers. Set either to 0 for unlimited or to a positive number for an enforced limit. Native reads process environment variables, while Workers reads the corresponding values from wrangler.toml [vars]. Quota checks are performed atomically in SQL.

## Storage

The native database and D1 both store up to 8 MiB per revision in 512 KiB chunks. The D1 backend writes its revision metadata and chunks in a transactional SQL batch; a trigger moves the HEAD and prunes versions. Native SQLite performs the equivalent operations in a transaction. This schema supersedes the initial whole-BLOB prototype and does not migrate existing prototype databases.

## Deployment

The Dockerfile produces a statically linked executable in a scratch image. Mount a writable /data directory for UID 65532. The image workflow publishes to GHCR on master pushes and version tags.

Cloudflare deployment is manual via the Cloudflare workflow, requiring CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID GitHub secrets and KEYLITE_D1_DATABASE_ID plus KEYLITE_WORKER_URL repository variables. The workflow applies migrations, deploys and verifies that the protected API returns HTTP 401 to an unauthenticated request. See docs/deployment.md for details.

## History

The former repository history was intentionally reset when this implementation replaced the initial prototype.
