# AGENTS.md

Working guide for AI agents in the wingsvpn-federation repository. Read this first. When a
rule is marked HARD RULE or MANDATORY, follow it exactly - the user has corrected these
before in the sibling WINGS V repos.

## 1. What this is

wingsvpn-federation is the control plane for the WINGS V free-VPN federation: any admin can
donate a server's capacity to a shared pool under a declared monthly traffic budget, and
free users get profiles served from that pool.

One Go binary, `cmd/wingsv-fed`, with subcommands picking the role:

- `agent` - runs on a donated node, supervises Xray and vk-turn-server, streams stats.
- `head` - runs alongside the panel, owns the node registry, assignment and aggregation.
- `enroll` - one-shot join, called by the installer. Never a shell wrapper (see section 6).
- `probe` - a vantage point inside the censored network. It measures by pulling
  bytes through a node, not by checking a handshake: nodes are far more often
  shaped than blocked, and a reachability check reports a shaped node as healthy.
- `scan` - find dests worth borrowing a TLS identity from (see section 7).
- `doctor`, `version` - support triage.

Ecosystem (sibling repos, out of scope here): the Android client
(../../../android/projects/apps/WINGSV), the desktop client WINGSV_DeX, the panel
v.wingsnet.org, the vk-turn-proxy relay, and the WINGS-N/3x-ui fork. All under the WINGS-N
GitHub org.

## 2. Layout

```
cmd/wingsv-fed/        role dispatch
proto/                 federation.proto (agent<->head), headpanel.proto (panel<->head)
gen/fedpb, gen/headpb  PUBLIC generated stubs
pkg/                   PUBLIC api surface: agentclient, fedstats, nodeid, receipt
internal/agent/        supervisor, xrayproc, xrayapi, xraycfg, vktpctl, binfetch,
                       realitykeys, passport, state
internal/head/         fedserver, headserver, registry, aggregator, assign,
                       allocator, profiles, probes, rotation, subs, tokens,
                       oracle, payout
internal/probe/        the vantage-point client
internal/scan/         reality dest scanner: tls probe plus a real handshake
internal/common/       tokenaead
deploy/                join.sh (go:embed), wingsv-fed.service
```

**The 3x-ui fork will never join the federation** (decided 2026-08-30). A donated node runs
our agent and a bare Xray under it, and nothing else. That was the only reason `pkg/` and
`gen/` were public, so the old hard rule about never touching their signatures is gone with
it: they have no external importer and are free to change. Do not reintroduce a 3x-ui
federation path, and do not contort a design to keep one possible.

## 3. Why code was ported rather than imported

Every reusable package in the 3x-ui fork lives under `internal/`, so Go's internal-package
rule makes importing it as a module dependency impossible. What was reusable was therefore
ported, once, and the fork is not a consumer of anything here.

Ported here (keep the provenance comment at the top of each file):

- `internal/agent/xrayproc` from 3x-ui `internal/xray/process.go`, `log_writer.go`
- `internal/agent/xrayapi` from 3x-ui `internal/xray/api.go`, reduced to QueryStats,
  AlterInbound and the traffic regexes - a full port drags in every proxy protocol
- `internal/scan` from 3x-ui `internal/web/service/reality_scan.go`
- `internal/common/tokenaead` from v.wingsnet.org `internal/tokenaead`

Xray's own control API is **vendored as proto, not imported as a Go module**
(`proto/vendored/xray/`, generated into `gen/xraypb`). Only the messages the agent
actually uses are declared, with the package names and field numbers copied from the
WINGS-N fork so the wire form is identical - `TypedMessage.type` is resolved by full
proto name on the core's side, so those names are load-bearing. Importing
`github.com/xtls/xray-core` instead would put a whole proxy stack inside a binary that
every donated node downloads, to call four RPCs.

## 4. Crypto rules

- Hashing is **SHA-512 or SHA-512/256**. Do not introduce SHA-256.
- `internal/common/tokenaead` derives with SHA-512 and keeps SHA-256 reachable as
  `Legacy256`, because the rest of the fleet is still migrating. A listener built with
  `ServerAny` accepts both: the transport has no handshake, so it resolves the derivation by
  trying the first record, which GCM's tag makes unambiguous. A dialer built with `ClientFor`
  tries SHA-512 and remembers per peer. Do not delete the legacy path until every deployed
  3x-ui node and vk-turn-proxy relay reports `sha512` - the servers log which derivation each
  peer arrived on precisely so that is answerable.
- The **shared secret** for a 3x-ui link stays the token's SHA-256 digest even on the SHA-512
  derivation: `x-ui grpc-connect` never stores a raw token, so that digest is the only value
  both peers hold. Changing that is a re-provisioning flag day; changing the derivation is not,
  which is exactly why the two were separated.
- Symmetric AEAD is AES-256-GCM. AES-512 does not exist (FIPS-197 defines 128/192/256 only)
  and AES-256 is already adequate against quantum search. The real limit in GCM is the nonce
  space, so watch nonce generation and key rotation instead of reaching for a longer key.
- A node reports `aes_ni` in its passport and the head puts the better WRAP cipher in the
  profile it hands out. This is a hint carried in config, NOT a handshake negotiation - the
  DTLS exchange is untouched.
- REALITY private keys are generated on the node and never leave it. Only the public halves
  travel, in `ConfigAck`.

## 5. Privacy invariants (MANDATORY)

- A donor sees aggregates only. There must be no RPC in `internal/head/headserver` that maps
  a node to profile ids or to user identity. The donor-to-profile join lives only inside
  `internal/head/assign`.
- The federation DOES look at where traffic goes, deliberately. Free access with no
  inspection gets eaten by farms, resellers and outright fraud, and none of that is
  distinguishable from ordinary use by counters alone. `internal/agent/domainwatch`
  subscribes to the core over gRPC (`app/wingswatch` in the Xray fork), folds a window into
  per-domain counters and ships them up. The rules that still hold, and must not be relaxed:
  - Only metered federation profiles. `MeteredProfiles` is the gate and there is no other
    path; the Xray and the relay the agent runs carry federation profiles and nothing else.
  - The node stores nothing. The window is folded in memory, sent, and forgotten; nothing is
    written to a donor's disk, and the text access log is not used at all.
  - Observations expire. `pgstore.DomainRetention` is thirty days and the sweeper runs
    hourly. This is not a data hoard.
  - A domain is never shown to a donor. It reaches the owner console only.
- `AbuseSignal` still carries a class, a count and a window - it is the cheap real-time
  signal, built from Xray's own online-address list, and it stays that way.
- Signals name a profile because that is all a node knows. `allocator.UserForProfile` is the
  only place the two are joined, and `internal/head/enforce` is the only thing that acts on a
  verdict - scoring and acting are kept apart because a wrong score is an opinion while a
  wrong revocation is a user with no internet.
- The panel-facing service is guarded by a test, not just by review:
  `internal/head/headserver` fails its build if any message reachable from
  `headpanel.proto` grows a field naming a profile, a client or a user.
- Nothing identifying reaches a node: `profile_id` is a random UUID and the Xray email tag is
  `f-<random8>`, never a handle or an address.

## 6. What a node's address is worth

An address a node reports about itself proves nothing: it may be behind NAT, on a
floating IP the interface never holds, or on a route the provider nulled after a
complaint. `passport.Addresses` therefore only collects **public** addresses, and
an operator pins the rest with `enroll -address`.

What decides is `assign.Options.RequireProbe`: with it on, only an address a
vantage point has recently carried traffic over is handed out. It is off by
default and turned on by the operator with `head -require-probe`, deliberately
rather than automatically - flipping it the moment a probe appears means one
dying vantage point silently parks the whole fleet.

## 7. Choosing a REALITY dest

Do not choose one by hand or by reasoning about it. `wingsv-fed scan` answers it,
and `head -reality-auto` does the same at startup and configures itself.

The reason is that **nothing observable predicts the answer**. Measured on Xray
26.3.27 and on the fork at v26.7.11, which behave identically:

| dest | handshake bytes | plain REALITY | with ML-DSA-65 |
|---|---|---|---|
| `yandex.ru` | 3995 | works | works |
| `www.cloudflare.com` | 3888 | works | fails |
| `www.wildberries.ru` | 4879 | works | fails |
| `music.yandex.ru` | 4605 | works | works |
| `habr.com` | 3240 | fails | - |
| `www.microsoft.com` | 9895 | fails | - |

A smaller handshake carries the signature while a larger one does not, and a host
can pass every TLS check and still fail REALITY outright. So `internal/scan` has
two halves: a cheap TLS probe that culls the obvious rejects, and `Verify`, which
stands up a throwaway REALITY server and client and pulls a byte through. Only the
dest handshake leaves the machine; the rest is loopback.

`RealityIdentity.post_quantum` is off unless a real handshake proved it works. A
security feature that silently bricks the fleet is worse than not having it: when
the signature does not fit, the node starts, ports listen, heartbeats are green,
and nobody can connect.

h2 is a **preference, not a requirement**. 3x-ui's scanner insists on it; REALITY
does not care. `360.yandex.ru`, `sso.passport.yandex.ru` and
`smartcaptcha.yandexcloud.net` all refuse h2, all carry REALITY with ML-DSA-65,
and all three are in production use in the list the app ships as its default
subscription. Culling on h2 threw away working dests.

Scanning also grows the pool: a certificate's SANs are usable dests in their own
right, so `music.yandex.ru` yields the `.uz`, `.by`, `.kz` and `music.ya.ru`
names, each looking like a different destination to anyone watching. Two hosts
expand to about thirty candidates.

`scan.RussianPool` is seeded from github.com/zieng2/wl, the public VLESS list the
app ships as `XrayStore.DEFAULT_SUBSCRIPTION_URL`, so its entries are known to
work in the field rather than merely to look plausible. All 32 pass; only
`www.vk.com` and `eh.vk.com` fail to carry ML-DSA-65.

To debug a dest by hand, set `"show": true` in `realitySettings` on both ends: a
matching `AuthKey` means REALITY authenticated and the fault is later, while
`REALITY: processed invalid connection` means auth itself failed.

## 8. Only federation profiles are metered (MANDATORY)

The Xray and the vk-turn relay the agent starts are the federation's own processes, on the
federation's own ports. A donor's paying customers live in a separate installation (their
own 3x-ui, their own relay) that this agent never connects to and never sees.

Every profile these processes serve is a federation profile, issued to a user running our own
app, so receipts, Oracle scoring and metering apply to all of them. `ProfileSpec.metered`
stays in the wire and in the gates as the marker of a profile that is accounted for: a
profile issued without it is never asked for a receipt and never scored.

The same applies to watching: `abusewatch` only ever asks the core about the profiles
`supervisor.MeteredProfiles` returns, and a test holds that line.

## 9. Installer rules

The installer is `deploy/join.sh`, go:embed'd and served by the head.

HARD RULE: never install a shell wrapper named `wingsv-fed` on PATH. The panel's `connect.sh`
carries a whole marker-string workaround (`xui_exec`) that exists only because a shell wrapper
named `x-ui` swallowed unknown subcommands and exited 0, so a failed setup reported success.
One binary, one path, exit code is the contract, plus a machine-readable last line.

Enrollment happens in Go (`wingsv-fed enroll`), never in shell - the shell must not touch a
credential. Reject a literal `<token>` placeholder; somebody will paste it.

Preflight failures abort loudly. Do not silently fall back to another port: the port is part
of the reachability contract the head will probe.

## 10. Code-text style

Same as the sibling repos:

- ASCII only in anything written into the source tree: `-` not an em-dash, straight quotes,
  `...` not the ellipsis character, words not arrow glyphs.
- No markdown in code comments: no backticks, no bold, no angle-bracket placeholders, no
  bracket links. Plain prose; name a symbol by writing its name.
- Comments only for genuinely non-obvious WHY. Do not restate what the code does.

## 11. Gates

Before every commit: `gofmt -l .` clean, `go vet ./...`, `golangci-lint run`, `go test ./...`.

## 12. Commits

Format: `[scope] short lowercase imperative` - a single subject line, NO colon after the
scope, NO body, NO Co-Authored-By or AI-mention trailer. Sign every commit.

Scopes: `[agent]`, `[head]`, `[probe]`, `[proto]`, `[deploy]`, `[pkg]`, `[docs]`,
`[build]`, `[ci]`, `[ignore]`.

Do NOT `git push` without explicit user confirmation. Commit, then stop and report.
