Deployment
==========

Native: Build with cargo build --release -p keylite-native and run with KEYLITE_LISTEN and KEYLITE_DB. The image workflow builds linux/amd64 and linux/arm64 scratch-based images and pushes to ghcr.io/softplus10/keylite. Supply a writable /data volume owned by UID 65532.

The following two variables are shared by the native and Workers deployments:

* KEYLITE_MAX_USERS: 0 means unlimited, positive values cap account registrations.
* KEYLITE_MAX_VAULTS_PER_USER: 0 means unlimited, positive values cap per-user vault creation.

For Workers, edit wrangler.toml [vars]. Set GitHub secrets CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID, and repository variable KEYLITE_D1_DATABASE_ID. Create a D1 database named keylite, then run the manual Cloudflare workflow. It applies migrations remotely and deploys.

Both backends limit an entire uploaded vault to 8 MiB. D1 has a 2 MB maximum BLOB/row size. The storage layer splits each version into 512 KiB chunks and stores up to 8 MiB per version.

Do not expose the API without HTTPS and request-rate limiting. Public registration is enabled when KEYLITE_MAX_USERS=0.
