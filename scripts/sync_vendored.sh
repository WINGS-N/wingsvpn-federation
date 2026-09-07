#!/usr/bin/env bash
set -euo pipefail
# Refreshes the vendored relay contract from the WINGS-N fork. Override the repo
# or ref with VKTP_REPO / VKTP_REF.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VKTP_REPO="${VKTP_REPO:-https://github.com/WINGS-N/vk-turn-proxy.git}"
VKTP_REF="${VKTP_REF:-main}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
git clone --quiet --depth 1 --filter=blob:none --sparse --branch "$VKTP_REF" "$VKTP_REPO" "$tmp"
git -C "$tmp" sparse-checkout set proto >/dev/null
sed 's|option go_package = "github.com/cacggghp/vk-turn-proxy/controlpb;controlpb";|option go_package = "wingsnet.org/federation/gen/controlpb;controlpb";|' \
  "$tmp/proto/control.proto" > "$ROOT/proto/vendored/control.proto"
echo "synced control.proto from $VKTP_REPO@$VKTP_REF"
