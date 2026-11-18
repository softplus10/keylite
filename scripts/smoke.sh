#!/usr/bin/env bash
set -euo pipefail
export KEYLITE_DB="$(mktemp -u /tmp/keylite-smoke-XXXX.sqlite)"
export KEYLITE_LISTEN=127.0.0.1:18787
export KEYLITE_MAX_USERS=1
export KEYLITE_MAX_VAULTS_PER_USER=1
if [ -z "${KEYLITE_SMOKE_URL:-}" ]; then
  cargo run -p keylite-native &
  pid=$!
  trap 'kill "$pid" 2>/dev/null || true; rm -f "$KEYLITE_DB" "$KEYLITE_DB-wal" "$KEYLITE_DB-shm"' EXIT
else
  export KEYLITE_LISTEN="${KEYLITE_SMOKE_URL#http://}"
fi
for i in $(seq 1 200); do
  if curl -s "http://$KEYLITE_LISTEN/api/vaults" >/dev/null; then break; fi
  sleep 0.2
done
base="http://$KEYLITE_LISTEN/api"
http() { curl -sS -o /tmp/keylite-output -w "%{http_code}" "$@"; }
code=$(http -H 'Content-Type: application/json' -d '{"email":"a@example.org","password":"correct horse battery staple"}' "$base/register")
test "$code" = 201
code=$(http -H 'Content-Type: application/json' -d '{"email":"b@example.org","password":"correct horse battery staple"}' "$base/register")
test "$code" = 403
code=$(http -H 'Content-Type: application/json' -d '{"email":"a@example.org","password":"correct horse battery staple"}' "$base/login")
test "$code" = 200
token=$(jq -r .token </tmp/keylite-output)
code=$(http -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -d '{"name":"primary"}' "$base/vaults")
test "$code" = 201
id=$(jq -r .id </tmp/keylite-output)
code=$(http -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -d '{"name":"secondary"}' "$base/vaults")
test "$code" = 403
code=$(http -X PUT -H "Authorization: Bearer $token" -H 'If-Match: *' --data-binary 'first-version' "$base/vaults/$id")
test "$code" = 200
hash=$(jq -r .head.hash </tmp/keylite-output)
code=$(http -X PUT -H "Authorization: Bearer $token" -H 'If-Match: *' --data-binary 'stale-version' "$base/vaults/$id")
test "$code" = 412
for i in 2 3 4 5 6 7; do
  code=$(http -X PUT -H "Authorization: Bearer $token" -H "If-Match: \"blake3:$hash\"" --data-binary "version-$i" "$base/vaults/$id")
  test "$code" = 200
  hash=$(jq -r .head.hash </tmp/keylite-output)
done
code=$(http -H "Authorization: Bearer $token" "$base/vaults/$id/history")
test "$code" = 200
test "$(jq length </tmp/keylite-output)" = 5
test "$(jq '.[0].revision' </tmp/keylite-output)" = 7
code=$(http -H "Authorization: Bearer $token" "$base/vaults/$id/history/1")
test "$code" = 404
code=$(http -H "Authorization: Bearer $token" "$base/vaults/$id")
test "$code" = 200
test "$(cat /tmp/keylite-output)" = version-7
python3 - <<'PY'
from pathlib import Path
Path('/tmp/keylite-large.bin').write_bytes(bytes(range(256)) * 12288)
PY
code=$(http -X PUT -H "Authorization: Bearer $token" -H "If-Match: \"blake3:$hash\"" --data-binary @/tmp/keylite-large.bin "$base/vaults/$id")
test "$code" = 200
code=$(http -H "Authorization: Bearer $token" "$base/vaults/$id")
test "$code" = 200
cmp /tmp/keylite-large.bin /tmp/keylite-output
rm -f /tmp/keylite-large.bin
code=$(http -X POST -H "Authorization: Bearer $token" "$base/logout")
test "$code" = 204
code=$(http -H "Authorization: Bearer $token" "$base/vaults")
test "$code" = 401
echo "Native smoke test passed."
