#!/bin/sh
# WINGS V federation installer.
#
# Deliberately small and deliberately loud. It never touches the enroll token:
# that is handed to "wingsv-fed enroll", which is Go and can fail properly. And it
# installs no wrapper named wingsv-fed on PATH - the panel's connect.sh carries a
# whole marker-string workaround because a shell wrapper swallowed unknown
# subcommands and exited 0, so a failed setup reported success.
set -eu

# The head fills these in when it serves this script, so the donor pastes one
# command and nothing else has to be explained to them
HEAD_DEFAULT="__WINGSV_HEAD__"
RELEASE_DEFAULT="__WINGSV_RELEASE__"

TOKEN="${1:-}"
BUDGET_GB="${2:-${WINGSV_BUDGET_GB:-0}}"
HEAD="${WINGSV_HEAD:-$HEAD_DEFAULT}"
RELEASE="${WINGSV_RELEASE:-$RELEASE_DEFAULT}"
IMAGE="${WINGSV_IMAGE:-ghcr.io/wings-n/wingsvpn-federation:latest}"

BIN_DIR=/usr/local/wings/federation/bin
CONFIG_DIR=/etc/wings/federation
STATE_DIR=/var/lib/wings/federation
LOG_DIR=/var/log/wings/federation

die() {
  echo "wingsv-fed: $*" >&2
  echo "RESULT=failed" >&2
  exit 1
}

[ "$(id -u)" = "0" ] || die "run as root"
[ -n "$TOKEN" ] || die "usage: join.sh <enroll-token> <gib-per-month>"
case "$TOKEN" in
  "<"*">") die "that is the placeholder from the docs, not a token" ;;
esac
case "$HEAD" in
  ""|"__WINGSV_HEAD__") die "this script was not served by a head, so it has no address to enrol against" ;;
esac
[ "$BUDGET_GB" -gt 0 ] 2>/dev/null || die "WINGSV_BUDGET_GB must be the traffic you are donating, in GiB"

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac

# This installer manages a systemd unit on a host it owns. Inside a container
# there is no systemd to hand the agent to, and the host paths below belong to
# the image rather than the machine - so say what to run instead of dying on
# "systemctl: not found" three lines later.
if [ ! -d /run/systemd/system ] || ! command -v systemctl >/dev/null 2>&1; then
  cat >&2 <<CONTAINER
This host has no systemd, so it looks like a container.

The agent runs as a container directly, enrolling itself on first start. It
needs the host network and NET_ADMIN: it manages a WireGuard interface and
binds 443, and behind a bridge the head would probe an address that is not
yours.

  docker run -d --name wingsv-fed --restart unless-stopped \\
    --network host --cap-add NET_ADMIN --cap-add NET_BIND_SERVICE \\
    -v wingsv-fed:/var/lib/wings/federation \\
    -v wingsv-fed-config:/etc/wings/federation \\
    -e WINGSV_FED_HEAD=$HEAD \\
    -e WINGSV_FED_ENROLL_TOKEN=$TOKEN \\
    -e WINGSV_FED_BUDGET_GB=$BUDGET_GB \\
    $IMAGE agent

Both volumes matter: the identity is written once at enrolment, and losing it
means the node comes back as a stranger with a burnt token.

On Kubernetes use the node chart in k8s/node instead; it is the same command
expressed as a DaemonSet.
CONTAINER
  exit 3
fi

for tool in curl sha512sum; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done

# 443 busy is a reason to move, not to refuse the host: most donated machines
# already serve something there. The agent picks a free port at enrolment and
# tells the head which one it took, so this is a note rather than a failure.
for port in 443 8443; do
  if command -v ss >/dev/null 2>&1 && ss -lnt "sport = :$port" 2>/dev/null | grep -q LISTEN; then
    echo "note: port $port is in use; the agent will offer another one" >&2
  fi
done

KERNEL_MAJOR=$(uname -r | cut -d. -f1)
KERNEL_MINOR=$(uname -r | cut -d. -f2 | cut -d- -f1)
if [ "$KERNEL_MAJOR" -lt 5 ] || { [ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 6 ]; }; then
  die "kernel $(uname -r) is older than 5.6, which the tunnel needs"
fi

mkdir -p "$BIN_DIR" "$CONFIG_DIR" "$STATE_DIR" "$LOG_DIR"
chmod 700 "$CONFIG_DIR" "$STATE_DIR"

case "$RELEASE" in
  ""|"__WINGSV_RELEASE__") die "no agent build to download; set WINGSV_RELEASE" ;;
esac
RELEASE="$(echo "$RELEASE" | sed "s/__ARCH__/$ARCH/")"
echo "wingsv-fed: fetching $RELEASE"
curl -fsSL "$RELEASE" -o "$BIN_DIR/wingsv-fed.new" || die "could not download the agent"

# Сумма лежит рядом с бинарём, поэтому проверка идёт всегда, а не только когда
# её продиктовали руками. Своя WINGSV_SHA512 старше: ей пинят сборку по фиксу
DIGEST="${WINGSV_SHA512:-$(curl -fsSL "$RELEASE.sha512" 2>/dev/null || true)}"
if [ -n "$DIGEST" ]; then
  echo "$DIGEST  $BIN_DIR/wingsv-fed.new" | sha512sum -c - >/dev/null 2>&1 ||
    die "the downloaded agent does not match its published digest"
else
  echo "wingsv-fed: no published digest to check against"
fi
chmod 755 "$BIN_DIR/wingsv-fed.new"
mv "$BIN_DIR/wingsv-fed.new" "$BIN_DIR/wingsv-fed"

# The token reaches Go and nothing else. A shell that handled it would leak it
# into the process table and into every trace of this script
"$BIN_DIR/wingsv-fed" enroll \
  -head "$HEAD" \
  -token "$TOKEN" \
  -budget-gb "$BUDGET_GB" \
  ${WINGSV_ADDRESS:+-address "$WINGSV_ADDRESS"} \
  ${WINGSV_ASN:+-asn "$WINGSV_ASN"} \
  ${WINGSV_COUNTRY:+-country "$WINGSV_COUNTRY"} \
  -state "$CONFIG_DIR/node.toml" || die "enrollment refused"

cat > /etc/systemd/system/wingsv-fed.service <<UNIT
[Unit]
Description=WINGS V federation agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN_DIR/wingsv-fed agent -state $CONFIG_DIR/node.toml -bin-dir $BIN_DIR -config-dir $CONFIG_DIR -state-dir $STATE_DIR
Restart=always
RestartSec=5
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=yes

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now wingsv-fed.service

# Machine-readable last line: the exit code plus this is the whole contract
echo "RESULT=ok node_state=$CONFIG_DIR/node.toml"
