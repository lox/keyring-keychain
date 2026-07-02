#!/usr/bin/env bash
set -euo pipefail

service="${KEYCHAIN_CLI_SERVICE:-keyring-keychain-terminal-smoke}"
key="${KEYCHAIN_CLI_KEY:-test-token}"
value="${KEYCHAIN_CLI_VALUE:-secret}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

go build -o "$tmp/keychain-cli" ./examples/keychain-cli
"$tmp/keychain-cli" -trust-application -service "$service" set "$key" "$value"
got="$("$tmp/keychain-cli" -trust-application -service "$service" get "$key")"
if [[ "$got" != "$value" ]]; then
  echo "expected $value, got $got" >&2
  exit 1
fi
"$tmp/keychain-cli" -trust-application -service "$service" remove "$key"
echo "$got"
