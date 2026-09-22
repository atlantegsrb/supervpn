# supervpn — Project Context

## What this is

supervpn is a custom L2 VPN system combining the roles of SoftEther VPN Bridge + Client
into a single client binary, and a multi-hub L2 server.

**Server (Linux):** Runs N independent Hubs. Each Hub is a transparent L2 broadcast domain —
it switches Ethernet frames between connected clients exactly like a network switch.

**Client (Windows/macOS, Go):** Detects network interfaces with 169.254.0.0/16 (link-local /
APIPA) addressing and transparently bridges all L2 traffic to the server hub. The client
combines the bridge + client roles.

## Key design decisions

| Topic | Decision | Reason |
|---|---|---|
| Transport | UDP primary + TCP fallback + Reality | FEC over UDP; TCP/TLS fallback; Reality (VLESS+Reality-style, uTLS browser fingerprint + dest fallback) for ТСПУ-grade DPI |
| Encryption | AES-128-GCM from internal/crypto | Taken verbatim from myvpn. Speed over strength. Works through ТСПУ. |
| FEC | Reed-Solomon/XOR matrix (SMPTE 2022-1 style) | Recovers from ≤5% random packet loss without retransmit |
| FEC negotiation | Server advertises K/R in AuthOK (+2 bytes) | Client auto-adopts server params; no manual config alignment needed |
| Delivery order | No concurrency-inflicted reordering; FEC-recovered frames arrive late by design | The FEC decoder releases frames in (blockID, pktIdx) order, but its callers run concurrently (server UDP worker pool, client dual-path recvLoops, stale flush). A per-session `orderMu` makes decode→forward atomic so the VPN never injects reordering from its own parallelism — the class of bug that hurt UDS/ENET flashing. AES-GCM decryption stays parallel (outside the lock). Note this is *not* absolute in-order under loss: a recovered packet is delivered when its repair arrives (~repair_delay) or on stale-flush (~200 ms), so it can land after later blocks. That is an intentional latency-vs-order tradeoff — a strict cross-block gate would add head-of-line blocking — and the inner TCP (DoIP/ENET) reassembles by sequence number, tolerating it. The **fragmentation path (FrameDataFrag) has no mutual ordering with the FEC path**; it only carries oversized non-TCP frames (MSS-clamped TCP never fragments), so this does not affect flashing. |
| MTU / large frames | TCP MSS clamping (default 1300) + VPN-level fragmentation on UDP | A full 1514 B inner frame + overhead (proto 15 + crypto 40 + IP/UDP 28) = ~1597 B > 1500 MTU → IP-fragments, and fragmented UDP is DPI/NAT-dropped. This quietly broke sustained streams (ISTA reads, UDS flashing over DoIP/ENET TCP) while short traffic (coding, Tool32) worked. Fix 1: `[bridge] mss_clamp` rewrites the MSS option in bridged TCP SYNs so inner TCP never emits fragmenting segments (both directions, `internal/bridge/mssclamp.go`). Fix 2: for large *non-TCP* frames MSS can't shrink, `internal/fragment` splits them into `FrameDataFrag` pieces (negotiated via AuthOK `FlagFragment`, UDP-only) reassembled before forward. The normal FrameData/FEC path is untouched. |
| Authentication | Login + password (bcrypt stored, SHA-256 wire) | Simple, no PKI required |
| Server language | Go | Fast development, excellent networking, single binary deploy |
| Client language | Go | Same codebase, cross-compile to Windows/macOS |
| Windows GUI | Walk (Win32/GDI default) + Fyne (-tags fyne) | Walk works on RDP/Hyper-V without GPU; Fyne for native look |
| Windows capture | WinTun (WireGuard driver) | Signed, modern, no NDIS complexity |
| TAP driver | Embedded in exe, auto-installed via pnputil | No external tools; pnputil built into Windows Vista+ |

## GitHub accounts & remotes

| Repo | Visibility | Purpose | git remote |
|---|---|---|---|
| `atlanteg/supervpn` | **Public** | Source code mirror | `origin` |
| `atlantegsrb/supervpn` | **Public** | CI/CD (GitHub Actions build & release) | `new-origin` |
| `atlanteg/supervpn-releases` | **Public** | Release hosting | — |

- All three repos are **public** (made permanently public 2026-06-19 at the
  user's request — no more flipping to private). Because `atlantegsrb/supervpn`
  is public, its GitHub Actions minutes are **unlimited/free**, so the old
  "make CI repo public temporarily for free minutes, then revert" dance is gone.
- Before going public a scan confirmed no tokens/private keys/FA archives are
  committed (`.gitignore` covers `reality-private-pool.toml`, `*.key`, `.env`,
  `tests_FA_all/`). Keep it that way — never commit those.
- Source of truth: push every commit to **both** remotes.
  - `git push origin main` — always (mirror, no CI)
  - `git push new-origin main` — triggers CI; **ask user before pushing here**
    (no longer a cost concern — just to avoid unnecessary CI runs/releases)
- `gh` CLI is authenticated as `atlanteg`; it **cannot** edit `atlantegsrb/supervpn`
  (404). For API calls against the CI repo, use the PAT embedded in the
  `new-origin` remote URL: `GH_TOKEN=$(git remote get-url new-origin | sed -E 's#.*:([^@]+)@.*#\1#') gh api ...`.
- The embedded `new-origin` PAT **lacks the `workflow` scope**, so it cannot push
  commits that touch `.github/workflows/` (GitHub rejects them) and it also made
  `gh release create`'s tag path fail with a spurious "workflow scope may be
  required". Both gh-keyring tokens (`atlanteg`, `atlantegsrb`) DO have `workflow`.
  To push a workflow-file change to the CI repo:
  `git push "https://atlantegsrb:$(gh auth token --user atlantegsrb)@github.com/atlantegsrb/supervpn.git" main`.
  The release job now creates the release via REST API (`gh api POST .../releases`),
  which sidesteps the scope error; normal (non-workflow) commits still push fine
  via the plain `new-origin` remote.
- CI builds at `atlantegsrb/supervpn`, then the release job **auto-publishes the
  same tag + 17 assets to all three repos**: `atlanteg/supervpn-releases`
  (required — the update system reads from it), `atlantegsrb/supervpn` (via the
  built-in `GITHUB_TOKEN`), and `atlanteg/supervpn`. See the `publish_to()` helper
  in `.github/workflows/ci.yml`. No more manual copying.
- The update system reads releases from `atlanteg/supervpn-releases`.

### Known server IPs (update mirrors)

All 5 servers are hardcoded in `internal/update/update.go` → `knownServerIPs`:

```
81.27.241.25
185.108.16.16
212.48.224.5
162.55.48.218
49.13.4.85
```

Each server exposes `GET /update/version` and `GET /update/{asset}` on **:993**
(IMAPS — privileged, near-universally firewall-allowed, rarely DPI-filtered, and
free of the nginx-on-:80 conflict). `update_listen` defaults to `:993`; clients
use `:993` only (`update.mirrorPorts`).

### Update chain (all binaries)

```
GitHub → HTTP mirrors (:993 on the 5 IPs) → in-band Reality from peers
```

- GitHub API: `https://api.github.com/repos/atlanteg/supervpn-releases/releases/latest`
- Download base: `https://github.com/atlanteg/supervpn-releases/releases/download/{tag}/{asset}`
- All clients and **servers** follow the same fallback chain.
- Servers host `supervpn-server` in their mirror dir; `handleUpdateAsset` and the
  in-band handler also serve the server's **own running exe**, so any live server
  seeds peers even if it couldn't fetch its own asset from GitHub.
- **In-band Reality fallback** (`internal/update/inband.go`): when GitHub and the
  HTTP mirrors are blocked (aggressive DPI), the binary is pulled from a peer over
  the DPI-resistant Reality transport (`FrameUpdateGet`/`FrameUpdateData`, pre-auth).
  This is the unblockable last resort — if the VPN transport works, updates work.

### Release procedure

1. `git push new-origin main` — triggers CI at `atlantegsrb/supervpn`
2. Wait for CI to pass (`gh run watch ... --repo atlantegsrb/supervpn`)
3. Download artifacts: `gh run download {run_id} --repo atlantegsrb/supervpn --dir /tmp/svpn-artifacts`
4. Read version: `strings .../supervpn-server | grep -E '^b[0-9]+$'`
5. Publish release: `gh release create b{N} --repo atlanteg/supervpn-releases --title "b{N}" ...files...`
6. Assets to include in every release:
   - `supervpn-server` (linux/amd64)
   - `supervpn-client-windows-amd64.exe`
   - `supervpn-client-darwin-amd64` / `supervpn-client-darwin-arm64`
   - `supervpn-client-linux-amd64` / `supervpn-client-linux-arm64`
   - `supervpn-client-gui-windows-amd64.exe`
   - `supervpn-client-gui-windows-386.exe` (32-bit Win7)
   - `supervpn-client-gui-darwin-amd64` / `supervpn-client-gui-darwin-arm64`
   - `supervpn-seema-windows-amd64.exe`
   - `supervpn-bmgarage-windows-amd64.exe`
   - `supervpn-dist.zip`, `README-user.pdf`

## Repository structure

```
cmd/
  supervpn-server/        — server entrypoint
  supervpn-client/        — headless CLI client entrypoint
  supervpn-client-gui/    — GUI client (Walk/Win32 default; Fyne with -tags fyne)
  supervpn-client-seema/  — stripped pre-configured client for seema hub (Windows only)
  supervpn-client-bmgarage/ — same, pre-configured for the bmgarage hub (hub 5)
internal/
  crypto/            — AES-128-GCM, ReplayWindow (verbatim from myvpn)
  proto/             — wire frame format
  fec/               — Forward Error Correction (Reed-Solomon/XOR)
  transport/         — UDP + TCP transport abstraction
  hub/               — server L2 hub / MAC table / forwarding
  bridge/            — client 169.254 detection + L2 bridge logic
  auth/              — login/password auth
  config/            — TOML config structures
  update/            — self-update logic (GitHub + mirror fallback)
  zgw/               — BMW ZGW discovery + FA-trained VIN decoder (used by clients)
pkg/
  tun/               — platform TAP/WinTun (linux, windows build tags)
standalone/
  bmwzgw/            — standalone BMW ZGW module (own go.mod) for 3rd-party integrations
tools/
  vin-retrain/       — retrain the VIN decoder from FA backups (see docs/vin-decoder.md)
```

## Rules for all agents

- **Never modify internal/crypto/** — it is taken verbatim from myvpn and must stay identical.
- After every commit: `git push origin main` (public mirror). **Never push to `new-origin` without asking the user** — it triggers CI and costs build minutes.
- No external dependencies except: `golang.org/x/crypto`, `golang.org/x/sys`,
  `golang.zx2c4.com/wintun`, `github.com/pelletier/go-toml` (or BurntSushi/toml),
  and `github.com/refraction-networking/utls` **pinned to v1.6.3** (Reality client
  ClientHello fingerprint; approved by user). **Do NOT upgrade utls past v1.6.3** —
  v1.6.4+ require `go 1.21+`, and Go 1.21 dropped Windows 7 support. The whole project
  is pinned to **Go 1.20** for Win7 compatibility (last Go release supporting Win7/8/
  Server 2008/2012). utls v1.6.3 mimics Chrome 120 and pulls quic-go/circl/brotli/
  klauspost-compress transitively (all go ≤1.20-compatible).
- **Go 1.20 is a hard floor — keep all golang.org/x/* deps at go-1.20-compatible
  versions** (x/crypto ≤ v0.33.0, x/sys ≤ v0.30.0, etc.). Newer x/crypto (v0.36+)
  requires go 1.23 and will break the Win7 build.
- **Reality is zero-config & default-on:** an empty server config runs Reality
  (stealth VLESS+Reality) on **:443** with the built-in default key pool, dest
  `www.gstatic.com:443`. Plain TLS/TCP defaults to **:8443**. Disable Reality
  with `[reality].disable = true`. Client `transport="reality"` defaults SNI to
  `www.gstatic.com` and the server addr to `<server>:443`; `public_key` is
  optional (random pick from the embedded pool).
- **Reality key pool:** the client embeds a pool of server **public** keys
  (`internal/transport/reality_pool.go`, committed) and picks one at random per
  connection. The matching **private** keys live only in `reality-private-pool.toml`
  (gitignored) and are deployed to servers via `[reality].private_keys`. **NEVER
  commit private keys or ship them in any binary.** Regenerate with
  `supervpn-server reality-genpool N`.
- **BMW VIN decoder (`internal/zgw` + `standalone/bmwzgw`):** chassis/model/
  platform are resolved primarily from FA-learned tables (`fa_typekeys.go`,
  `fa_platform.go`, generated — ~99% accurate), with a single-char `VIN[3]`
  heuristic fallback. The two locations are kept in sync. To retrain on new FA
  backups: `python3 tools/vin-retrain/retrain.py <fa-dir>` then
  `go test ./internal/zgw -run FAAccuracy -v`. Full details + accuracy:
  **docs/vin-decoder.md**. Raw FA archives are gitignored — never commit them
  (may contain real customer VINs); commit only the generated tables.
- Do not add comments explaining WHAT the code does — only WHY when non-obvious.
- Server targets Linux amd64. Client targets Windows amd64 (macOS is secondary).
- FEC parameters K and R must be configurable at runtime, not compile-time constants.
- When adding a new release asset: add its name to **both** `clientAssets` in `cmd/supervpn-server/main.go` AND to the CI release upload step in `.github/workflows/ci.yml`.

## Agents

### architect
**Role:** Protocol and component interface design.
**Owns:** internal/proto, interfaces between packages, wire format decisions.
**Authority:** Final say on any change to packet format or inter-component API.
**Trigger:** Before implementing any new protocol feature or changing Frame layout.

### protocol-engineer
**Role:** FEC implementation and transport reliability.
**Owns:** internal/fec, internal/transport.
**Focus:** Correct Reed-Solomon implementation, UDP/TCP switching logic,
congestion-friendly behavior (no retransmit, only FEC).
**Trigger:** Any change to FEC parameters, transport layer, or packet loss handling.

### server-dev
**Role:** Linux server implementation.
**Owns:** cmd/supervpn-server, internal/hub, internal/auth (server side).
**Focus:** Hub manager (create/delete/list hubs), session lifecycle, MAC table,
L2 forwarding correctness, concurrent client handling.
**Trigger:** Hub logic, session management, server main loop.

### windows-client-dev
**Role:** Windows client implementation.
**Owns:** cmd/supervpn-client, pkg/tun/tun_windows.go, internal/bridge.
**Focus:** WinTun integration, 169.254.0.0/16 interface detection, bridge loop,
Windows service wrapper (sc.exe / golang.org/x/sys/windows/svc).
**Trigger:** Any Windows-specific code or bridge logic.

### security
**Role:** Security audit.
**Owns:** Nothing directly — reviews crypto, auth, replay window usage.
**Focus:** Ensure AES-128-GCM nonce uniqueness, replay protection correctness,
no credential leakage in logs, auth protocol soundness.
**Trigger:** Before any release cut, or when crypto/auth code changes.

### devops
**Role:** Build, CI, packaging.
**Owns:** .github/workflows/, Makefile, build scripts.
**Focus:** Cross-compile client for windows/amd64 from Linux CI,
build server for linux/amd64, GitHub Actions, release artifact naming.
**Trigger:** CI failures, new platform targets, release preparation.

### qa-engineer
**Role:** Testing and loss simulation.
**Owns:** *_test.go files across all packages.
**Focus:** Unit tests for FEC (inject artificial losses), integration tests
for hub forwarding, transport fallback tests, crypto round-trip tests.
**Trigger:** New features, bug fixes, pre-release validation.

## Development workflow

1. Branch: work on `main` for now (small team).
2. Every meaningful change: `git add`, `git commit`, `git push origin main`.
3. Commits must be atomic — one logical change per commit.
4. Build check before commit: `make build` (or `go build ./...`).
5. To release: push to `new-origin` (**ask user first**), then follow the Release procedure above.
6. After CI passes: download artifacts and publish to `atlanteg/supervpn-releases` manually (see Release procedure).
