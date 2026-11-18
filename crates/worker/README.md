Cloudflare Workers backend
==========================

The workers-rs implementation exposes the same Keylite HTTP API using D1 storage. The shared keylite-core crate provides BLAKE3 hashing and CAS precondition logic. The D1 trigger updates the HEAD and prunes history atomically.

Configure a D1 database ID in wrangler.toml and run both migrations in order. Deployment is manual through .github/workflows/cloudflare.yml and requires repository secrets and variables. Keep independent backups and do not deploy publicly until the CI tests and security hardening pass.
