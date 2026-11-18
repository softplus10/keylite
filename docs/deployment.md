# Deployment

## Cloudflare Workers Builds

The `Hanseung Kim` Cloudflare account owns the `keylite` D1 database, bound as `DB` in `wrangler.toml`. The account's Workers Builds integration is connected directly to `softplus10/keylite`, production branch `master`.

Cloudflare Builds provisions Rust and the `wasm32-unknown-unknown` target, compiles `crates/worker` with `worker-build`, and deploys via Wrangler. There is no GitHub Actions production deployment workflow for Cloudflare.

The runtime variables `KEYLITE_MAX_USERS` and `KEYLITE_MAX_VAULTS_PER_USER` are configured in `wrangler.toml`. A value of `0` means unlimited, and a positive integer is the maximum number of users or vaults per user.

D1 schema changes must be applied before incompatible code is deployed. Initial tables and CAS trigger are installed. Future migrations should be tracked through Wrangler/D1 migration records to avoid unintentional repeat application.

## Self-hosted

Build with `cargo build --release -p keylite-native`, or build and run the scratch container. The GitHub Container workflow publishes multi-architecture images to GHCR and the regular CI tests the native and Workers APIs.

Mount a writable `/data` volume owned by UID 65532 for the scratch image. The database is stored in `/data/keylite.sqlite`.

Set the following environment variables as needed:

- `KEYLITE_MAX_USERS=0` — unlimited users (positive values cap registrations)
- `KEYLITE_MAX_VAULTS_PER_USER=0` — unlimited vaults per user (positive values cap vault creation)
- `KEYLITE_LISTEN=0.0.0.0:8787`
- `KEYLITE_DB=/data/keylite.sqlite`

Both backends store vault blobs in 512 KiB chunks, with an 8 MiB per-version limit. The server does not interpret or decrypt KDBX files.

**Important:** This is experimental software. Protect public endpoints with HTTPS and rate limiting; retain independent backup copies of vaults and validate restore procedures before relying on the service.
