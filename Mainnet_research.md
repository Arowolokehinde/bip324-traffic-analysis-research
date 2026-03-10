# Passive Traffic Analysis of BIP-324 Encrypted Bitcoin P2P Connections

**Author:** Arowolo Kehinde
**Date:** March 2026
**Reference:** https://github.com/0xB10C/project-ideas/issues/12
**Network:** Bitcoin Mainnet
**Bitcoin Core Version:** v28.1 (both nodes)

---

## Abstract

This report investigates whether a passive network adversary — such as an Internet
Service Provider (ISP) or a BGP-hijacking attacker positioned on the network path —
can determine the timing of specific Bitcoin P2P protocol events from encrypted
traffic metadata alone. The experiment targets Bitcoin's V2 encrypted transport
protocol (BIP-324), which uses ChaCha20Poly1305 authenticated encryption to conceal
message content, but which explicitly acknowledges that traffic analysis through
packet lengths and timing may still reveal protocol usage.

Two Bitcoin Core nodes are connected over a real internet link: Node A on a first
DigitalOcean server (Server 1, Ubuntu 24.04) and Node B on a second DigitalOcean
server (Server 2, Ubuntu 24.04). Node B's chain data was bootstrapped from Node A
via rsync over the private network. The Bitcoin connection uses public IPs so traffic
traverses the real network stack and is captured on Server 1's external interface
(eth0). Two 120-minute captures were conducted — one with full transaction relay
enabled, one with blocksonly mode — while an unfiltered all-peers capture ran in
parallel to simulate the ISP view, and continuous RTT measurements separated network
latency from Bitcoin Core processing time. A dedicated short capture recorded the
BIP-324 connection handshake for protocol fingerprint analysis.

A per-second event visibility ratio metric was applied across both captures,
measuring traffic volume at the exact second an event occurred relative to a
rolling 60-second baseline, to determine whether each event type is
distinguishable from background noise.

---

## 1. Background and Research Questions

### 1.1 BIP-324: Encrypted Bitcoin P2P Transport

BIP-324 introduces mandatory encrypted transport for Bitcoin peer-to-peer connections.
Prior to BIP-324, Bitcoin messages were transmitted in plaintext, allowing any
on-path observer to read message types, content, and peer relationships directly.
BIP-324 replaces this with ElligatorSwift ECDH key exchange, ChaCha20Poly1305
authenticated encryption, and short encrypted message type identifiers.

BIP-324 itself is explicit about its limitation:

> "Traffic analysis, e.g., observing packet lengths and timing, as well as active
> attacks can still reveal that the Bitcoin v2 P2P protocol is in use."

### 1.2 BIP-152: Compact Block Relay

Under BIP-152, a node sends only a ~10 KB compact block summary instead of the
full 1–4 MB block. The receiving node reconstructs the full block from transactions
already in its mempool. Block relay traffic on a node with a warm mempool is reduced
from megabytes to hundreds or thousands of bytes — often indistinguishable from
ordinary transaction traffic.

However, when compact block reconstruction fails (because the receiving node lacks
some transactions), the full block must be downloaded. This creates a large,
distinctive traffic burst — a real-world failure mode not captured by idealized
protocol analysis.

### 1.3 Research Questions

1. Can a passive network attacker — observing only encrypted traffic metadata
   (per-packet timestamps and sizes) — identify when specific Bitcoin P2P
   protocol events occurred on a target node?

2. Does the answer depend on node configuration — specifically, whether the node
   runs in full-relay or blocksonly mode?

3. Can the BIP-324 / ElligatorSwift connection handshake itself be identified from
   packet sizes and timing, without reading any payload?

4. Is a specific peer's block arrival event visible to an ISP observing all of a
   node's Bitcoin traffic (not just the single peer link)?

5. How much of compact block reconstruction time is attributable to network
   transit latency vs Bitcoin Core internal processing?

---

## 2. Threat Model

The adversary is a **passive network observer** on the path between the target
Bitcoin node and at least one of its peers:

- An ISP that carries the node operator's traffic
- A BGP-level attacker who has hijacked the route to a peer AS
- A colocation provider with access to the physical or virtual network link

**The attacker can observe:** exact packet timestamps, byte sizes,
source/destination IP and port, direction, and aggregate traffic volume at
any time resolution.

**The attacker cannot observe:** message content (encrypted by ChaCha20Poly1305),
message type, or the application-layer identity of peers.

---

## 3. Experimental Setup

### 3.1 Infrastructure

| Component | Details |
|-----------|---------|
| Node A — Server 1 | DigitalOcean, Ubuntu 24.04 LTS, Amsterdam (AMS3) |
| Node B — Server 2 | DigitalOcean, Ubuntu 24.04 LTS, Amsterdam (AMS3) |
| Bitcoin Core | v28.1 (both nodes) |
| Network | Bitcoin Mainnet |
| Capture interface | eth0 on Server 1 (external NIC, public traffic) |
| Transport | BIP-324 V2 encrypted (confirmed via `getpeerinfo`) |
| Chain data transfer | rsync via private IP (Server 1 private IP → Server 2 private IP) |
| Bitcoin connection | addnode uses Server 1's public IP on port 8333 |
| Node A public IP | <redacted> |
| Node B public IP | <redacted> |

### 3.2 Node A — Server 1 Configuration

- Listening on port 8333, full transaction relay
- `debug=net,mempool,cmpctblock`, `logtimemicros=1`
- Firewall open on port 8333 (node has existing external peers)
- Fully synced to chain tip before captures begin
- Data directory: `/nodes/nodeA`

### 3.3 Node B — Server 2 Configuration

- Chain data bootstrapped via rsync from Server 1 over private IP
- `prune=5000` (~5 GB disk usage)
- `listen=0` (no inbound connections — outbound-only)
- `addnode=<NODE_A_IP>:8333` (connects to Node A via public IP)
- `debug=net,mempool,cmpctblock`, `logtimemicros=1`
- Data directory: `/nodes/nodeB`
- **capture_001:** full-relay (default, no `blocksonly`)
- **capture_002:** `blocksonly=1`

### 3.4 Captures Conducted

| Capture | Config | Duration | Purpose |
|---------|--------|----------|---------|
| capture_bip324_handshake | N/A | ~40 packets | BIP-324 handshake fingerprint |
| capture_001_mainnet | Full-relay | 116.4 min | Event visibility, full-relay |
| capture_001_allpeers | Full-relay (all peers) | 116.4 min | ISP-view simulation |
| capture_002_mainnet | Blocksonly | 166.0 min | Event visibility, blocksonly |
| capture_002_allpeers | Blocksonly (all peers) | 166.0 min | ISP-view simulation |

---

## 4. Analysis Methodology

### 4.1 Event Visibility Ratio

```
r(T) = traffic_bytes(T) / mean(traffic_bytes over [T − 60s, T + 60s], excluding T)
```

- `r > 2.0`: event second carries more than twice the baseline — likely detectable
- `r ≈ 1.0`: indistinguishable from background
- `r < 1.0`: event second is quieter than the surrounding baseline

Resolution: per-second. No knowledge of what event occurred is required.

### 4.2 Event Types

| Event Type | Detection Source | Filter |
|-----------|-----------------|--------|
| Block arrival | `UpdateTip:` in debug log | `progress=1.` (chain tip only) |
| Compact block | `received: cmpctblock` | Any |
| Address dump | `received: addr/addrv2` | Size > 1,000 bytes |
| Large transaction | `received: tx` | Size > 10,000 bytes |

### 4.3 Compact Block Reconstruction Time

```
reconstruction_time = UpdateTip_timestamp − cmpctblock_timestamp
```

Compared against concurrent RTT measurement to separate network latency
from internal processing time.

### 4.4 Handshake Fingerprint Analysis

The BIP-324 handshake capture is analysed with `analyze_handshake.py`, which
computes the symmetry ratio (first responder packet / first initiator packet)
and compares it against known protocol fingerprints for BIP-324, TLS 1.3, and SSH.

| Protocol | First initiator pkt | First responder pkt | Ratio |
|----------|--------------------|--------------------|-------|
| BIP-324 | 80–4175 bytes (random) | 80–4175 bytes (random) | ≈ 1x |
| TLS 1.3 | 200–600 bytes (ClientHello) | 1500–10000 bytes (cert chain) | 3–50x |
| SSH | ~22 bytes (plaintext banner) | ~22 bytes (plaintext banner) | ≈ 1x (but plaintext) |

---

## 5. Results

### 5.1 BIP-324 Handshake Fingerprint

Capture: `capture_bip324_handshake.pcap` — 40 packets, 29K
Analysis: `analysis/analyze_handshake.py`

| Metric | Value |
|--------|-------|
| Total packets captured | 40 |
| Data packets (tcp.len > 0) | 26 |
| Data packets from initiator (Node B) | 12 |
| Data packets from responder (Node A) | 14 |
| First initiator packet (TCP payload) | **3,784 bytes** |
| First responder packet (TCP payload) | **2,356 bytes** |
| Symmetry ratio (resp / init) | **0.62x** |
| Total bytes from initiator | 5,254 |
| Total bytes from responder | 20,911 |
| Handshake duration (first to last pkt) | **17.2 ms** |

**Protocol fingerprint verdict:**

| Protocol | Criteria met | Verdict |
|----------|-------------|---------|
| BIP-324 / ElligatorSwift | 3/3 | **CONSISTENT** |
| TLS 1.3 | 1/3 (ratio failed) | **INCONSISTENT** |
| SSH | 1/3 | POSSIBLE (sizes completely outside range) |

**Interpretation:** The handshake is definitively consistent with BIP-324's
ElligatorSwift design. Both first packets fall within the 80–4175 byte range
(64-byte key + random garbage + 16-byte terminator). The 0.62x symmetry ratio
is within BIP-324's expected near-symmetric range and completely outside TLS
1.3's required 3–50x asymmetric range. TLS 1.3 is ruled out. SSH is ruled out
by packet sizes (3,784 and 2,356 bytes vs SSH's 15–55 byte plaintext banners).

A passive attacker can determine from packet metadata alone that this is NOT
TLS 1.3 and is consistent with BIP-324 or another pseudorandom-bytestream
protocol (such as obfs4).

---

### 5.2 RTT During Captures

Both servers are in the same DigitalOcean Amsterdam (AMS3) datacenter. RTT
is sub-millisecond on average, meaning network transit contributes negligibly
to block reconstruction times.

| Capture | RTT min (ms) | RTT avg (ms) | RTT max (ms) | RTT mdev (ms) |
|---------|-------------|-------------|-------------|--------------|
| capture_001 (full-relay) | 0.353 | **1.002** | 51.749 | 3.608 |
| capture_002 (blocksonly) | 0.336 | **1.001** | 78.489 | 3.511 |

One-way latency (RTT/2): ~0.5ms. RTT-adjusted reconstruction time differs
from raw reconstruction time by less than 1ms — negligible.

---

### 5.3 Capture 001 — Full-Relay Traffic Statistics

| Metric | Value |
|--------|-------|
| Capture period | 2026-03-06 17:48:08 → 19:44:32 UTC |
| Duration | 116.4 minutes |
| Total packets | 17,910 |
| Total bytes | 15,162,954 |
| Avg bytes/sec | **2,170.8** |
| Max bytes/sec | 6,755,013 (initial mempool sync at 17:48) |
| Blocks in window | 10 (blocks 939612–939621) |

**Note:** The max bytes/sec spike (6.75 MB/s at 17:48) is the initial mempool
synchronisation when Node B first connected, not a block event. This is the
largest single traffic event in the entire capture and would be trivially
visible to any passive observer.

**Figure 1 — Full-Relay Traffic vs Block Events (capture_001_mainnet.pcap)**

![Full-relay traffic plot showing bytes/sec over time with block arrival markers](analysis/plots/traffic_vs_blocks_capture_001_mainnet.png)

*Top panel: bytes/minute coarse view. Bottom panel: bytes/second timing precision
view. Red dashed lines = block arrivals (UpdateTip), orange = compact blocks,
green = addr/addrv2 dumps, blue = large transactions (>10 KB). The large spike
at 17:48 is the initial mempool sync burst (6.75 MB/s), not a block.*

---

### 5.4 Capture 001 — Full-Relay Event Visibility

| Event Type | Occurrences | Detectable (r > 2x) | Rate (n, 95% Wilson CI) | Avg Ratio |
|-----------|-------------|---------------------|------------------------|-----------|
| Block arrivals (UpdateTip) | 10 | **8/10** | **8 of 10 (80%; CI: 49–94%)** | 157.79x |
| Compact blocks (cmpctblock) | 25 | 16/25 | 16 of 25 (64%; CI: 45–80%) | 39.01x |
| addr/addrv2 dumps (>1 KB) | 3 | **0/3** | **0 of 3 (0%; CI: 0–56%)** | 0.27x |
| Large transactions (>10 KB) | 136 | 23/136 | 23 of 136 (17%; CI: 12–24%) | 4.62x |

> **Note on block sample size:** With only n=10 blocks in the full-relay capture, the
> 95% confidence interval is wide (49–94%). This rate should be treated as a pilot
> estimate. Replication with longer captures (~8 hours, ~50 blocks) is needed to
> narrow the interval.

**Block visibility detail:**

| Block | Time | Bytes@event | Baseline | Ratio | Visible? |
|-------|------|------------|---------|-------|---------|
| 939612 | 17:48:09 | 235 | 140,922 | 0.0x | no (masked by mempool sync) |
| 939613 | 17:50:56 | 19,103 | 678 | 28.2x | YES |
| 939614 | 18:06:43 | 22,379 | 1,094 | 20.5x | YES |
| 939615 | 18:15:25 | 21,300 | 650 | 32.8x | YES |
| 939616 | 18:25:49 | **308,411** | 910 | **339.0x** | YES (full block download) |
| 939617 | 18:28:05 | 6,598 | 879 | 7.5x | YES |
| 939618 | 18:31:09 | 7,724 | 2,446 | 3.2x | YES |
| 939619 | 18:49:42 | 797 | 625 | 1.3x | no (compact block, warm mempool) |
| 939620 | 19:00:44 | 18,716 | 728 | 25.7x | YES |
| 939621 | 19:02:49 | **820,858** | 733 | **1,119.8x** | YES (full block download) |

**Key finding on blocks:** Two blocks triggered full block downloads (308 KB and
820 KB) because compact block reconstruction failed — Node B lacked the required
transactions. When compact blocks work (warm mempool), blocks can be invisible
(939619: 1.3x). When they fail, the full 1–4 MB download creates an enormous,
unmissable spike. This is a critical real-world deviation from the idealized
BIP-152 model.

**Compact block reconstruction times (Capture 001):**

| Block | Reconstruction time (ms) | RTT-adjusted (ms) |
|-------|--------------------------|-------------------|
| 939612 | 195 | 194.5 |
| 939613 | 326 | 325.5 |
| 939614 | 165 | 164.5 |
| 939615 | 121 | 120.5 |
| 939616 | 329 | 328.5 |
| 939617 | 80 | 79.5 |
| 939618 | 34 | 33.5 |
| 939619 | 423 | 422.5 |
| 939620 | 149 | 148.5 |
| 939621 | 598 | 597.5 |
| **Average** | **242.0 ms** | **241.5 ms** |

---

### 5.5 Capture 002 — Blocksonly Traffic Statistics

| Metric | Value |
|--------|-------|
| Capture period | 2026-03-09 07:19:11 → 10:05:14 UTC |
| Duration | 166.0 minutes |
| Total packets | **1,250** |
| Total bytes | **460,141** |
| Avg bytes/sec | **46.2** |
| Max bytes/sec | 311,526 (full block download at 08:11:17) |
| Blocks in window | 29 (blocks 939951–939979) |

**Traffic volume ratio vs full-relay:** 460,141 / 15,162,954 = **0.030x** (97% less traffic).
Average bytes/sec: 46.2 vs 2,170.8 = **47x reduction**.

The 46.2 bytes/sec baseline consists entirely of Bitcoin Core's heartbeat
PING/PONG messages. Between block arrivals, the link is nearly silent.

**Figure 2 — Blocksonly Traffic vs Block Events (capture_002_mainnet.pcap)**

![Blocksonly traffic plot showing near-silent baseline with clear block arrival spikes](analysis/plots/traffic_vs_blocks_capture_002_mainnet.png)

*Top panel: bytes/minute coarse view. Bottom panel: bytes/second timing precision
view. Red dashed lines = block arrivals (UpdateTip), orange = compact blocks,
blue = large transactions (>10 KB). Note the near-silent baseline (~46 bytes/sec)
compared to Figure 1. The two large spikes at 08:07 and 08:11 are full block
downloads (42 KB and 311 KB) due to compact block reconstruction failure. Even
the smallest compact block announcement (235 bytes) stands 15–35x above the
quiet baseline.*

---

### 5.6 Capture 002 — Blocksonly Event Visibility

| Event Type | Occurrences | Detectable (r > 2x) | Rate (n, 95% Wilson CI) | Avg Ratio |
|-----------|-------------|---------------------|------------------------|-----------|
| Block arrivals (UpdateTip) | 29 | **27/29** | **27 of 29 (93%; CI: 78–98%)** | 1,428.71x |
| Compact blocks (cmpctblock) | 56 | 38/56 | 38 of 56 (68%; CI: 55–79%) | 1,473.68x |
| addr/addrv2 dumps (>1 KB) | 0 | 0/0 | N/A (no events) | N/A |
| Large transactions (>10 KB) | 201* | 12/201 | 0% true visibility (see note*) | 4.27x |

*Large tx events in the debug log reflect transactions Node A received from
other peers. Node B does not relay transactions in blocksonly mode — 94% of
these events show 0 bytes on the Node A↔Node B link. The remaining 6% (12 events)
show small amounts of traffic (169–644 bytes) that are coincidental PING/PONG
heartbeats or block-coincident messages, not the transaction itself. No actual
transaction data crossed the Node A↔Node B link in blocksonly mode.

**Block visibility detail (sample):**

| Block | Time | Bytes@event | Baseline | Ratio | Visible? |
|-------|------|------------|---------|-------|---------|
| 939951 | 07:27:15 | 235 | 10.1 | 23.4x | YES |
| 939957 | 08:00:03 | 235 | 10.1 | 23.3x | YES |
| 939959 | 08:06:34 | 235 | 365.5 | 0.6x | no (masked by prior block traffic) |
| 939960 | 08:07:27 | **42,297** | 10.2 | **4,129.9x** | YES (full block download) |
| 939961 | 08:11:17 | **311,526** | 8.5 | **36,758.2x** | YES (full block download) |
| 939965 | 08:26:41 | 235 | 11.9 | 19.7x | YES |
| 939970 | 09:21:20 | 235 | 7.1 | 32.9x | YES |
| 939974 | 09:50:23 | 235 | 6.8 | 34.7x | YES |

Even a minimal 235-byte compact block announcement is 15–35x above the 46
bytes/sec baseline. Blocks are almost always detectable.

**Compact block reconstruction times (Capture 002):**

| Statistic | Value |
|-----------|-------|
| Minimum | 27 ms |
| Maximum | 675 ms |
| Average | **300.1 ms** |
| RTT-adjusted average | **299.6 ms** |
| Sample size | 29 blocks |

---

## 6. Full-Relay vs Blocksonly Comparison

| Metric | Full-Relay (capture_001) | Blocksonly (capture_002) |
|--------|--------------------------|--------------------------|
| Duration | 116.4 min | 166.0 min |
| Total packets | 17,910 | 1,250 |
| Total bytes | 15,162,954 | 460,141 |
| Avg bytes/sec | 2,170.8 | **46.2** |
| Traffic reduction | baseline | **97% less** |
| Block visibility | 8/10 — **80% (95% CI: 49–94%)** | 27/29 — **93% (95% CI: 78–98%)** |
| Block avg ratio | 157.79x | **1,428.71x** |
| Large tx visible | 23/136 — **17% (95% CI: 12–24%)** | 0% true visibility* |
| addr visible | 0/3 — **0% (95% CI: 0–56%)** | 0 events |
| Avg reconstruction (raw) | 242.0 ms | 300.1 ms |
| Avg reconstruction (RTT-adj) | 241.5 ms | 299.6 ms |
| RTT avg | 1.002 ms | 1.001 ms |

*In blocksonly mode, large tx events show 0 bytes in 94% of cases since Node B
does not participate in transaction relay. The 6% that show as "visible" (12/201)
are coincidental heartbeat or block-coincident traffic in the same second — not
actual transaction content. True transaction visibility on this link is 0%.

**Comparison against prior work (BitSniff era):**

| Property | BitSniff Era (V1, pre-BIP-152) | This Study (V2 BIP-324, BIP-152) |
|---------|-------------------------------|----------------------------------|
| Block relay size | ~1–4 MB per block | ~235 bytes (compact) or full download if reconstruction fails |
| Block visibility (full-relay) | ~100% | 8/10, 80% (95% CI: 49–94%) |
| Block visibility (blocksonly) | N/A | 27/29, 93% (95% CI: 78–98%) |
| Dominant noise source | Block relay | Transaction relay (full-relay) / heartbeat (blocksonly) |
| Handshake identifiable | N/A (plaintext) | INCONSISTENT with TLS 1.3 by metadata alone |

---

## 7. Answers to Research Questions

**RQ1 — Can a passive attacker identify Bitcoin events from encrypted metadata?**

Yes, for some event types. Detectability varies significantly by event type
and node configuration:

- **Block arrivals:** In our sample, 8 of 10 blocks (80%; 95% CI: 49–94%) were
  detectable in full-relay, and 27 of 29 blocks (93%; 95% CI: 78–98%) were
  detectable in blocksonly. The full-relay interval is wide due to the small
  sample (n=10) and should be replicated with longer captures. Compact block
  reconstruction failures cause full block downloads (308 KB–820 KB) that are
  impossible to miss. Even successful compact block relay produces spikes of
  17–35x above baseline in blocksonly mode.
- **Large transactions:** In our sample, 23 of 136 large transactions (17%;
  95% CI: 12–24%) were detectable in full-relay. Only the largest outliers spike
  above the INV noise floor. In blocksonly mode, true transaction visibility is
  **0%**: no transaction data crosses the Node A↔Node B link at all. The 12/201
  events the script counts as "visible" are coincidental heartbeat traffic, not
  transaction content. Transaction relay flows from Node B toward Node A (Node B
  broadcasts txids via INV, then delivers raw transactions on demand); Node A
  sends zero outbound transactions to Node B over this link.
- **Address exchanges (getaddr responses):** In our sample, 0 of 3 addr events
  (0%; 95% CI: 0–56%) were detectable. With only 3 observations the upper bound
  is wide; a longer capture with more addr events would tighten this. The getaddr
  response at connection time is buried under the 6.75 MB/s mempool sync burst;
  mid-session addr messages are too small to clear the INV baseline.

**RQ2 — Does node configuration determine detectability?**

Yes, significantly. In our sample, blocksonly mode:
- Reduces average traffic volume by 97% (2,171 → 46 bytes/sec)
- Makes blocks MORE visible — 27/29 (93%; CI: 78–98%) vs 8/10 (80%; CI: 49–94%)
  — by eliminating transaction noise
- Makes transactions completely invisible on the monitored link (0% true visibility)

A passive observer can fingerprint node configuration from average traffic volume
alone: 46 bytes/sec strongly suggests blocksonly, 2,000+ bytes/sec suggests
full-relay.

**RQ3 — Can the BIP-324 handshake be identified by metadata alone?**

Partially. The handshake is **CONSISTENT with BIP-324** (3/3 criteria) and
**INCONSISTENT with TLS 1.3**. A passive observer can determine from the 0.62x
symmetry ratio that this is not a TLS 1.3 connection (which would show 3–50x).
The observer cannot distinguish BIP-324 from other pseudorandom-bytestream
protocols (e.g., obfs4) by these metrics alone.

**RQ4 — Is a block arrival visible in the all-peers (ISP) view?**

The all-peers captures collected 74 MB (full-relay) and 157 MB (blocksonly) of
traffic across all Node A peers. Node B's traffic (15 MB, 469 KB respectively)
represents a small fraction of total traffic, making it harder to isolate individual
peer events in the unfiltered stream. Full analysis of the all-peers captures
is left as future work.

**RQ5 — How much reconstruction time is network vs processing?**

With RTT avg of 1.002ms (one-way: ~0.5ms), network transit contributes less than
1ms to reconstruction times. Average reconstruction time was 242ms (full-relay)
and 300ms (blocksonly). Over **99.8% of reconstruction delay is Bitcoin Core
internal processing**, not network latency. The 58ms increase in blocksonly mode
may reflect additional getblocktxn round-trips due to colder mempool state.

---

## 8. Notable Unexpected Findings

### 8.1 Initial Mempool Sync is Highly Visible

On first connection, Node B synchronised its mempool with Node A, producing
a 6.75 MB/s burst at 17:48:08 UTC and 1.80 MB/s at 17:48:40 UTC. These are
the two largest traffic events in the entire 116-minute full-relay capture —
larger than any block event. A new connection establishment is a strong,
unambiguous fingerprint for a passive observer, even under BIP-324 encryption.

### 8.2 Compact Block Reconstruction Failures are Common

Two blocks in full-relay and two blocks in blocksonly triggered full block
downloads (308 KB, 820 KB, 42 KB, 311 KB) when compact block reconstruction
failed. This is a real-world deviation from the theoretical BIP-152 model and
substantially increases block visibility over what metadata-only analysis of
the protocol specification would predict.

### 8.3 Blocksonly Makes Blocks More, Not Less, Detectable

Counterintuitively, switching from full-relay to blocksonly mode increases block
detectability from 80% to 93%. By eliminating transaction noise, blocksonly
lowers the baseline from 2,171 bytes/sec to 46 bytes/sec, making even a 235-byte
compact block announcement 15–35x above background. A node operator choosing
blocksonly for privacy achieves privacy for transactions but at the cost of making
block arrival times highly visible.

### 8.4 INV Messages Dominate the Full-Relay Noise Floor

The 2,170 bytes/sec full-relay baseline is not random background — it is almost
entirely produced by Bitcoin `inv` inventory announcements. During the 116.4-minute
full-relay capture, Node A's debug log recorded **2,393 INV messages** relayed over
the Node A↔Node B link, averaging approximately 20.5 per minute.

Each INV message announces the txid of a new unconfirmed transaction Node A has
received from its other peers. Node B receives these announcements, issues `getdata`
requests for transactions it has not yet seen, and Node A delivers the transaction
data. This creates a continuous, roughly uniform stream of small messages that
constitutes the noise floor.

**Implication for detectability:** Large transactions (>10KB) must exceed this INV
flood to become visible. Only 17% do. The INV baseline is not a privacy feature by
design — it is an artifact of the mempool propagation protocol — but it incidentally
provides cover for individual transaction events.

**In blocksonly mode** Bitcoin Core sets `feefilter` to `MAX_MONEY`
(21,000,000 BTC expressed in satoshis) when connecting to peers, signalling
"do not send me any transactions." Peers honour this and stop sending INV
announcements. The INV flood stops entirely, reducing baseline traffic by 97%
to 46 bytes/sec (heartbeat PING/PONG only). This is why block detection improves
in blocksonly mode: the INV noise that was masking blocks has been removed.

### 8.5 Traffic on the Link is Directionally Asymmetric

Analysis of the debug log for the capture-window connection (peer=156, connected
17:48:08 UTC) reveals that the Node A↔Node B link carries fundamentally different
traffic in each direction:

| Direction | Primary content | Protocol messages |
|-----------|----------------|-------------------|
| Node B → Node A | Transaction relay | `inv` (txids) → `tx` (raw transactions) |
| Node A → Node B | Block relay + peer discovery | `cmpctblock`, `blocktxn`, `addr`/`addrv2` |

Node A receives 0 outbound transaction messages from Node A to Node B. Node B
already receives transactions from its other public peers and announces them to
Node A via INV; there is nothing for Node A to push back.

**Implication for passive surveillance:** An ISP sitting on the upstream link of
Node A (between Node A and Node B) observes:
- Large bursts in the Node B→Node A direction = transaction relay activity
- Large bursts in the Node A→Node B direction = block relay activity

Even without decrypting any packet, flow direction alone is a partial event
classifier. A sophisticated observer can infer "Node A just received a block and
is forwarding it" from a directional burst on the Node A→Node B path.

### 8.6 getaddr Response is Not Visible at Connection Time or Mid-Session

The addr/addrv2 detection result (0/3 visible, avg 0.27x) covers only the three
addr events the analysis script found in the capture window, all occurring
mid-session at 19:03:13, 19:03:21, and 19:34:35 UTC.

The standard Bitcoin handshake includes a `getaddr` / `addrv2` exchange at
connection time (17:48:08 UTC). Node A's debug log records a 16,949-byte addrv2
peer-table message sent to Node B at connection. However, this event does not
appear in the analysis script's addr event list, almost certainly because 17:48:08
is the very first second of the capture: the 60-second rolling baseline had no
history yet, so the script excluded it from the ratio calculation. The event is
real (confirmed in the debug log) but sits outside the analysis window boundary.

Had the analysis captured it, the ratio would have been approximately
`16,949 / 6,755,013 ≈ 0.003x` — the addrv2 is dwarfed by the 6.75 MB/s
mempool sync burst occurring in the same second. Even if the two events were
separated by one second, the rolling baseline would be dominated by the mempool
sync, keeping the ratio well below 1x.

The three mid-session addr events confirm the steady-state result: addr messages
are too small (0 bytes on the link in two cases, 6,138 bytes in one case against
a 7,514-byte baseline giving 0.82x) to clear the detection threshold.

**Conclusion:** addr/addrv2 responses are not detectable whether they occur at
connection time (dwarfed by mempool sync) or mid-session (insufficient volume
relative to baseline). This is a genuine privacy benefit of the current Bitcoin
P2P design for peer discovery traffic.

---

## 9. Limitations

**Two nodes only.** A production Bitcoin node has 8–125 peer connections.
With 10 peers, transaction noise is amplified 9× by relay forwarding. The
results here reflect a minimal two-node setup.

**Same datacenter.** Both servers are in the same DigitalOcean Amsterdam
datacenter, producing sub-millisecond RTT. Different geographies would show
higher network latency contributions to reconstruction times.

**Small block sample.** 10 blocks (full-relay) and 29 blocks (blocksonly).
A larger sample would narrow confidence intervals on detection rates.

**Single handshake capture.** One handshake sample is sufficient to observe
the structure but not sufficient for a statistical claim. Multiple captures
across different garbage lengths would strengthen the fingerprinting conclusion.

**Debug log as event source.** Event times come from Node A's debug log,
reflecting when Node A processed each event — not the exact moment traffic
crossed the wire. Discrepancy is typically sub-millisecond.

**All-peers capture not fully analysed.** The 74 MB and 157 MB all-peers
captures were collected but full per-event analysis against the multi-peer
stream is left as future work.

---

## 10. Conclusions

BIP-324 encryption successfully hides Bitcoin message content and type from
passive observers. However, traffic metadata — packet sizes and per-second
byte volumes — reveals substantial information about node behaviour:

1. **Block arrivals are detectable** in both full-relay (8/10, 80%; 95% CI:
   49–94%) and blocksonly (27/29, 93%; 95% CI: 78–98%) mode. The full-relay
   estimate is based on a small sample (n=10) and carries a wide confidence
   interval; the blocksonly estimate (n=29) is more reliable. Compact block
   reconstruction failures create full block downloads that are impossible to
   conceal. Even successful compact block relay is visible in blocksonly mode
   due to the near-silent baseline.

2. **Node configuration is fingerprintable** from average traffic volume.
   46 bytes/sec (blocksonly) vs 2,171 bytes/sec (full-relay) are clearly
   distinguishable without reading any packet content.

3. **The BIP-324 handshake is distinguishable from TLS 1.3** by the symmetry
   ratio of first packets (0.62x observed vs 3–50x required for TLS 1.3).
   A passive observer cannot mistake BIP-324 for TLS 1.3 based on metadata.

4. **Address exchanges and most transactions are well-hidden** in full-relay
   mode. The transaction noise floor (dominated by 2,393 INV messages in
   116 min) successfully masks addr events (0 of 3 visible; CI: 0–56%) and the
   majority of large transactions (23/136, 17% visible; CI: 12–24%). The addr
   sample is too small (n=3) to rule out occasional visibility; the transaction
   result (n=136) is more robust. The getaddr response at connection time is
   buried under the mempool sync burst; mid-session addr messages are too small
   to clear any baseline.

5. **New connection establishments are highly visible** regardless of mode.
   The initial mempool sync burst (6.75 MB/s) is the most distinctive event
   in the capture — more visible than any block arrival. The getaddr exchange
   at connection time is a secondary, invisible event in comparison.

6. **Reconstruction time is dominated by Bitcoin Core processing** (~242–300ms)
   not network latency (~0.5ms one-way), even for same-datacenter peers.

7. **Traffic direction is an additional side-channel.** Node B→Node A carries
   INV announcements and raw transactions; Node A→Node B carries compact
   blocks, full blocks, and addr messages. A passive observer can partially
   classify event type from flow direction alone, without decrypting content.

8. **Blocksonly eliminates the INV noise floor.** The 97% traffic reduction in
   blocksonly mode is not a compression improvement — it is the removal of the
   INV announcement flood. This is why block detectability increases (93% vs
   80%): the masking noise is gone, not because blocks became louder.

BIP-324 provides meaningful privacy against content-level surveillance but does
not hide the timing of block arrivals, node connection events, or the distinction
between full-relay and blocksonly operating modes from a passive observer with
access to packet metadata.

---

## 11. Future Work

- **Multi-peer captures** — repeat with Node A having 8–10 peers to measure
  how peer count amplifies the transaction noise floor.
- **All-peers capture analysis** — determine whether individual peer block
  arrival events are visible in the unfiltered ISP-view stream. The 74 MB
  (full-relay) and 157 MB (blocksonly) all-peers captures have been collected
  and are available for this analysis.
- **Multiple handshake captures** — build a distribution of symmetry ratios
  across 10–20 captures to confirm distinguishability statistically.
- **Padding countermeasures** — measure what constant-rate padding would be
  required to reduce block visibility in blocksonly mode below the 2x threshold.
- **Directional analysis** — apply direction-aware event classification to
  quantify whether flow direction (Node B→A vs Node A→B) improves or degrades
  a passive attacker's ability to distinguish block events from transaction events.
- **INV flood characterisation** — measure INV rate as a function of mempool
  size and network mempool propagation load to determine how much the noise
  floor varies over time and whether it can be predicted from public mempool data.
- **Geographic diversity** — repeat with servers in different regions/ASes to
  measure the effect of higher RTT on reconstruction time and detectability.

---

## 12. Tools and Data

| Tool | Version | Purpose |
|------|---------|---------|
| bitcoind | v28.1 | Running Bitcoin Mainnet nodes |
| tcpdump | Ubuntu 24.04 default | Packet capture to pcap |
| tshark | Ubuntu 24.04 default | Pcap parsing and field extraction |
| Python | 3.12 | Analysis scripting |
| pandas | latest | Per-second time series resampling |
| matplotlib | latest | Traffic volume plots |
| ping | Linux default | RTT measurement during captures |

**Capture files:**
- `captures/mainnet/capture_bip324_handshake.pcap` — 29 KB, 40 packets
- `captures/mainnet/capture_001_mainnet.pcap` — 15 MB, full-relay filtered
- `captures/mainnet/capture_001_allpeers.pcap` — 74 MB, full-relay all-peers
- `captures/mainnet/capture_002_mainnet.pcap` — 469 KB, blocksonly filtered
- `captures/mainnet/capture_002_allpeers.pcap` — 157 MB, blocksonly all-peers

**Analysis scripts:**
- `analysis/analyze_capture.py` — event visibility pipeline
- `analysis/analyze_handshake.py` — BIP-324 handshake fingerprint analysis

**Analysis outputs:**
- `analysis/analysis_handshake_bip324.txt`
- `analysis/analysis_001_mainnet.txt`
- `analysis/analysis_002_mainnet.txt`

---

## References

| Resource | URL |
|----------|-----|
| Research task (original issue) | https://github.com/0xB10C/project-ideas/issues/12 |
| BIP-324 specification | https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki |
| BIP-152 compact block relay | https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki |
| BitSniff (prior work) | https://79jke.github.io/BitSniff/ |
| Bitcoin Core v28.1 | https://bitcoincore.org/en/releases/28.1/ |
