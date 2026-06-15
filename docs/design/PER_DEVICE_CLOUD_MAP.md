# Per-device cloud-node visibility (Network Map)

## Problem

HomeGuard's Network Map shows every LAN device, but cloud (internet) edges only
hang off **this host** — because `ai_traffic` reads only the local machine's
socket table (`psutil`/`netstat`). It cannot see which internet endpoints *other*
LAN devices (NAS, TV, another PC, IoT) talk to, since HomeGuard has no agent on
those devices and does not capture packets.

## Core idea

Read the **router's connection table (conntrack)**, which already records every
`LAN-device → external-endpoint` mapping. Conntrack rows carry the **pre-NAT LAN
source IP**, so attribution to a device is direct and reliable, with **no packet
capture** by HomeGuard.

## Data-source options

| Phase | Source | Mechanism | Attribution | Effort |
| --- | --- | --- | --- | --- |
| **1 (this PR)** | Router conntrack via **SSH/API poll** | HomeGuard *initiates* a poll to the router | **Direct** (pre-NAT LAN IP per row) | M |
| 2 | **NetFlow v5** collector | HomeGuard listens on UDP:2055; router exports flow | Direct (full 5-tuple, unsampled) | L |
| 3 | NetFlow v9/IPFIX (+IPv6), **sFlow**, DNS/SNI enrichment | templated / sampled collectors + name resolution | v9/IPFIX direct; sFlow statistical | L |

### Why pull-based conntrack is Phase 1 (not a NetFlow collector)

For a **sterile-by-default security tool**, the pull model is clearly right:

- **Zero inbound attack surface** — HomeGuard initiates the connection; it never
  opens a listening UDP socket, so there is no spoofed/forged/oversized-packet or
  collector-DoS hardening burden (which is exactly what makes a NetFlow collector
  an L-effort security review).
- **Best attribution** — a conntrack row *is* the `LAN-ip ↔ WAN-ip` mapping
  (pre-NAT), so device attribution is exact, not inferred.
- **Best effort:value** — it ships the headline capability at M effort.

NetFlow (Phase 2) is the fallback for routers you can configure to *export* flow
but cannot SSH/API into.

## Phase-1 router connectors (pluggable)

A small connector interface, one implementation per router family:

| Router | Mechanism (read-only) |
| --- | --- |
| **OpenWrt / DD-WRT** | SSH `cat /proc/net/nf_conntrack` *(first target — simplest)* |
| OPNsense | REST `/api/diagnostics/firewall/...` (states/conntrack) |
| pfSense | SSH `pfctl -ss` (state table) |
| MikroTik RouterOS | REST / API `/ip/firewall/connection` |
| UniFi | Network controller API (active connections / DPI) |

Phase 1 ships the **OpenWrt conntrack-over-SSH** connector and the full data
path; the others are additive implementations of the same interface.

## Integration (reuse existing patterns)

- **Module** `flow_source.py`: a `FlowRecord` model, a pure
  `parse_nf_conntrack(text)` parser, a pure `classify_edges()` (uses stdlib
  `ipaddress`: private src + global dst), the `OpenWrtConntrackSource` (fetches
  via the system `ssh` client through `subprocess` — **no new runtime
  dependency**), and `collect_flow_edges(config)`.
- **Map schema** `network_map.build_network_map(*, flow_edges=...)`: merges
  device→cloud edges. The external `dst_ip` becomes a **shared cloud node**; a
  `kind:"cloud"` link is drawn from the matching device node (today such links
  attach only to the host). The existing SVG renderer already draws cloud edges.
- **Privacy plumbing**: endpoints flow through `ai_traffic._redact_remote` so the
  same `minimal`/`standard`/`full` share-levels apply when surfaced to the AI
  bridge. LAN src IPs map to device nodes by IP.
- **Credentials**: mirror the AI-bridge env-var pattern — settings store the
  router host/user and the **name** of an env var holding the SSH key path; the
  secret is resolved at call time and **never written** to settings.
- **Opt-in**: a `flow_source` settings block, **off by default** (sterile
  parity). The map shows per-device cloud edges only when explicitly enabled and
  configured.
- **Live-only in Phase 1**: flows are fetched on demand when building the map and
  **not persisted**, minimising the privacy footprint (no stored
  browsing-destination history).
- **Surface**: `GNHL flow status|test` CLI; the existing `network-map` command /
  IPC includes per-device edges when the source is enabled.
- **Test seams**: the parser and classifier are pure and unit-tested with
  conntrack fixtures; `build_network_map` is tested with injected `flow_edges`.

## Privacy & security model

Per-device destination data is effectively the **whole household's
browsing-destination history** — the most sensitive data HomeGuard would hold.

- **Explicit opt-in**, off by default, with disclosure that it captures *all*
  devices' external destinations (household-consent consideration).
- **Local-only**, no telemetry; Phase 1 keeps flows in memory only (no storage).
- **Read-only, least-privilege** router account; pull model = no listening socket.
- Reuse `ai_traffic` redaction share-levels for any AI-bridge exposure.
- (Phase 2 NetFlow only) bind the collector to the LAN interface, allow-list
  exporter IPs, bound packet sizes.

## Known limitation

Conntrack/flow endpoints are **IPs, not names**. CDNs (Cloudflare/Akamai/AWS)
front many services behind shared IPs, so `device → 142.250.x.x` under-identifies
the service. Pair with the existing **opt-in reverse-DNS** (and optional
passive-DNS / IP-reputation enrichment in Phase 3) for human-readable nodes.
