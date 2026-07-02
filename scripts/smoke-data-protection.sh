#!/usr/bin/env bash
set -euo pipefail

profile="${KEYCHAIN_CLI_PROFILE:-}"
if [[ -z "$profile" ]]; then
  echo "KEYCHAIN_CLI_PROFILE must point to a macOS provisioning profile with Keychain Sharing enabled" >&2
  exit 1
fi

identity="${KEYCHAIN_CLI_SIGN_IDENTITY:-}"
if [[ -z "$identity" ]]; then
  identity="$(security find-identity -v -p codesigning | awk -F '"' '/Apple Development|Developer ID Application/ { print $2; exit }')"
fi
if [[ -z "$identity" ]]; then
  echo "KEYCHAIN_CLI_SIGN_IDENTITY is required when no codesigning identity is available" >&2
  exit 1
fi

service="${KEYCHAIN_CLI_SERVICE:-keyring-keychain-data-protection-smoke}"
key="${KEYCHAIN_CLI_KEY:-test-token}"
value="${KEYCHAIN_CLI_VALUE:-secret}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

profile_plist="$tmp/profile.plist"
security cms -D -i "$profile" -o "$profile_plist"

app_id="$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:application-identifier' "$profile_plist" 2>/dev/null || true)"
if [[ -z "$app_id" ]]; then
  app_id="$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.application-identifier' "$profile_plist" 2>/dev/null || true)"
fi
if [[ -z "$app_id" ]]; then
  echo "profile does not contain an application identifier entitlement" >&2
  exit 1
fi

bundle_id="${KEYCHAIN_CLI_BUNDLE_ID:-${app_id#*.}}"
if [[ "$bundle_id" == "*" || "$bundle_id" == "$app_id" ]]; then
  echo "KEYCHAIN_CLI_BUNDLE_ID is required for wildcard provisioning profiles" >&2
  exit 1
fi

entitlements="$tmp/entitlements.plist"
/usr/libexec/PlistBuddy -x -c 'Print :Entitlements' "$profile_plist" >"$entitlements"

app="$tmp/KeychainCLI.app"
mkdir -p "$app/Contents/MacOS"
go build -o "$app/Contents/MacOS/keychain-cli" ./examples/keychain-cli
cp "$profile" "$app/Contents/embedded.provisionprofile"
cat >"$app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>keychain-cli</string>
<key>CFBundleIdentifier</key><string>$bundle_id</string>
<key>CFBundleName</key><string>KeychainCLI</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleVersion</key><string>1</string>
</dict></plist>
EOF

codesign -f -s "$identity" --entitlements "$entitlements" "$app"

cli="$app/Contents/MacOS/keychain-cli"
"$cli" -data-protection -user-presence -service "$service" set "$key" "$value"
got="$("$cli" -data-protection -user-presence -service "$service" get "$key")"
if [[ "$got" != "$value" ]]; then
  echo "expected $value, got $got" >&2
  exit 1
fi
"$cli" -data-protection -service "$service" remove "$key"
echo "$got"
