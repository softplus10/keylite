# Cloudflare Workers backend

This directory reserves the D1 backend. It is **not implemented** and is deliberately excluded from the Cargo workspace until it passes integration tests.

Target: \`workers-rs\` on Cloudflare Workers, with the shared \`keylite-core\` crate and Cloudflare D1. Authentication must operate within Workers runtime limits, and CAS must be implemented atomically with D1's supported SQL operations.

A whole-file BLOB schema is insufficient for D1's per-value limit. Implement chunked upload staging, atomic HEAD movement, and bounded revision garbage collection before enabling this backend. The native API is currently a prototype, not a production deployment.
