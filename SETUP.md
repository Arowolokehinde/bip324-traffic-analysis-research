# Reproduction Guide — BIP-324 Passive Traffic Analysis

This document provides a complete step-by-step guide to reproduce the experiment
described in [Mainnet_research.md](Mainnet_research.md). Follow the steps in order.
Every command shown was run during the original experiment.

---

## Prerequisites

### Cloud infrastructure

You need **two Linux servers** in the same datacenter or region with:
- Private networking enabled between them (same LAN)
- Public IPv4 addresses (Bitcoin connection must traverse the real network stack)
- At least **20 GB free disk** on each (Node A needs full UTXO set; Node B is pruned to 5 GB)
- Ubuntu 24.04 LTS (other Debian-based distros will work with minor adjustments)

This experiment used two DigitalOcean droplets in the Amsterdam AMS3 region.
A Basic 2 vCPU / 4 GB RAM / 80 GB SSD droplet is sufficient for each node.

> **Why same datacenter?** Bootstrapping the chain via rsync over the private
> network takes ~10 minutes instead of several days of initial block download.
> Bitcoin connections use the public IPs, so traffic still traverses the real
> network stack and is captured on the external NIC.

### Local machine

You need Python 3.10+ and the following packages to run the analysis scripts:

```bash
pip install pandas matplotlib
```

Or use the provided requirements file:

```bash
pip install -r requirements.txt
```

### Tools required on servers

```bash
# Install on both servers
sudo apt update && sudo apt install -y tcpdump tshark python3 python3-venv iputils-ping screen rsync
```

---

## Part 1 — Install Bitcoin Core on Both Servers

Run the following on **both Server 1 and Server 2**.

```bash
# Download Bitcoin Core v28.1
wget https://bitcoincore.org/bin/bitcoin-core-28.1/bitcoin-28.1-x86_64-linux-gnu.tar.gz

# Verify the download (check SHA256 against the official release page)
sha256sum bitcoin-28.1-x86_64-linux-gnu.tar.gz

# Extract and install
tar -xzf bitcoin-28.1-x86_64-linux-gnu.tar.gz
sudo install -m 0755 -o root -g root -t /usr/local/bin bitcoin-28.1/bin/*

# Verify
bitcoind --version
```

---

## Part 2 — Configure and Start Node A (Server 1)

Node A is the **listening node**. It accepts the inbound connection from Node B.
All packet captures run on this server's external NIC (`eth0`).

### 2.1 Create the data directory and config file

```bash
sudo mkdir -p /nodes/nodeA
```

Create `/nodes/nodeA/bitcoin.conf`:

```ini
# Node A — Server 1
# Full transaction relay, listening on mainnet port

# Network
listen=1
port=8333
bind=0.0.0.0

# Logging — needed for event timestamps
debug=net
debug=mempool
debug=cmpctblock
logtimemicros=1

# Data directory
datadir=/nodes/nodeA
```

### 2.2 Open the firewall

Node B must be able to reach Node A on port 8333:

```bash
sudo ufw allow 8333/tcp
sudo ufw status
```

### 2.3 Start Node A

```bash
# Use a screen session so it keeps running if you disconnect
screen -S nodeA

bitcoind -datadir=/nodes/nodeA -daemon

# Verify it started
bitcoin-cli -datadir=/nodes/nodeA getblockchaininfo
```

Detach from screen: `Ctrl+A` then `D`

### 2.4 Wait for full sync

Node A must be fully synced before you proceed. This can take 1–3 days on a
fresh machine over the internet.

```bash
# Monitor sync progress
watch bitcoin-cli -datadir=/nodes/nodeA getblockchaininfo
# Look for: "initialblockdownload": false
```

> **Shortcut:** If you have a trusted existing node with the same version, you
> can rsync its blocks/ and chainstate/ directories to Node A while it is stopped.

---

## Part 3 — Bootstrap Node B via rsync (Server 2)

Instead of waiting days for Node B to sync from scratch, copy Node A's chain
data over the **private network**.

### 3.1 Find the private IPs

```bash
# On Server 1 — note the private IP (usually eth1 on DigitalOcean)
ip addr show eth1 | grep "inet "
# Example: 10.110.0.3

# On Server 2
ip addr show eth1 | grep "inet "
# Example: 10.110.0.6
```

### 3.2 Stop Node A before copying

```bash
# On Server 1
bitcoin-cli -datadir=/nodes/nodeA stop
sleep 5
```

### 3.3 Create destination directory on Server 2

```bash
# On Server 2
sudo mkdir -p /nodes/nodeB
```

### 3.4 rsync the chain data (run from Server 2)

```bash
# On Server 2 — copy blocks and chainstate from Server 1's private IP
rsync -av --progress \
  root@<SERVER1_PRIVATE_IP>:/nodes/nodeA/blocks/ \
  /nodes/nodeB/blocks/

rsync -av --progress \
  root@<SERVER1_PRIVATE_IP>:/nodes/nodeA/chainstate/ \
  /nodes/nodeB/chainstate/
```

Replace `<SERVER1_PRIVATE_IP>` with the actual private IP (e.g., `10.110.0.3`).

This transfer takes approximately 10–15 minutes over the private network.

### 3.5 Restart Node A

```bash
# On Server 1
bitcoind -datadir=/nodes/nodeA -daemon
```

---

## Part 4 — Configure and Start Node B (Server 2)

### 4.1 Create the config file

Create `/nodes/nodeB/bitcoin.conf`:

```ini
# Node B — Server 2
# Pruned, outbound-only, connects only to Node A

# Connect only to Node A (use Node A's PUBLIC IP — not private)
listen=0
addnode=<NODE_A_PUBLIC_IP>:8333

# Pruning — keeps disk usage to ~5 GB
prune=5000

# Logging
debug=net
debug=mempool
debug=cmpctblock
logtimemicros=1

# Data directory
datadir=/nodes/nodeB
```

Replace `<NODE_A_PUBLIC_IP>` with Node A's actual public IP address.

> **Important:** Use the **public IP** for `addnode`, not the private IP.
> This ensures the Bitcoin connection travels over `eth0` on Server 1,
> where tcpdump will capture it.

### 4.2 Start Node B

```bash
screen -S nodeB
bitcoind -datadir=/nodes/nodeB -daemon
```

### 4.3 Verify the BIP-324 connection

Wait 30–60 seconds, then check on **Node A**:

```bash
bitcoin-cli -datadir=/nodes/nodeA getpeerinfo | grep -A5 '"addr"'
```

Look for Node B's public IP in the peer list. Verify the transport is V2 (BIP-324):

```bash
bitcoin-cli -datadir=/nodes/nodeA getpeerinfo | python3 -c "
import json, sys
peers = json.load(sys.stdin)
for p in peers:
    print(p['addr'], 'transport_version:', p.get('transport_protocol_name','?'))
"
```

You should see `transport_protocol_name: v2` for Node B's connection.

### 4.4 Wait for Node B to sync to chain tip

```bash
watch bitcoin-cli -datadir=/nodes/nodeB getblockchaininfo
# Wait until: "initialblockdownload": false
```

Both nodes must be at the same block height before captures begin.

---

## Part 5 — BIP-324 Handshake Capture

This short capture records only the connection handshake for fingerprint analysis.

### 5.1 Stop Node B

```bash
# On Server 2
bitcoin-cli -datadir=/nodes/nodeB stop
sleep 5
```

### 5.2 Start tcpdump on Server 1 (capture handshake only)

```bash
# On Server 1 — filter traffic to/from Node B's public IP
tcpdump -i eth0 -w /captures/mainnet/capture_bip324_handshake.pcap \
  host <NODE_B_PUBLIC_IP> and port 8333
```

Leave this running in a separate screen session.

### 5.3 Restart Node B and wait for connection

```bash
# On Server 2
bitcoind -datadir=/nodes/nodeB -daemon
```

### 5.4 Stop tcpdump once handshake is complete

Wait about 10–15 seconds after Node B starts (enough time to complete the
handshake), then stop tcpdump with `Ctrl+C`.

```bash
# Verify the capture has data
ls -lh /captures/mainnet/capture_bip324_handshake.pcap
# Expected: ~29 KB, ~40 packets
```

---

## Part 6 — Capture 001: Full-Relay (120 Minutes)

### 6.1 Ensure Node B is running in default (full-relay) mode

The `bitcoin.conf` from Part 4 already has full relay enabled (no `blocksonly=1`).
Confirm Node B is running and connected to Node A.

### 6.2 Note the peer ID for debug log queries

```bash
# On Server 1 — find Node B's peer ID
bitcoin-cli -datadir=/nodes/nodeA getpeerinfo | python3 -c "
import json, sys
peers = json.load(sys.stdin)
for p in peers:
    if '<NODE_B_PUBLIC_IP>' in p['addr']:
        print('Peer ID:', p['id'], '| Connected at:', p['conntime'])
"
```

Record this peer ID — you will need it to filter the debug log after the capture.

### 6.3 Start the capture (screen session recommended)

```bash
# On Server 1 — start tcpdump filtered to Node B traffic
screen -S capture001

mkdir -p /captures/mainnet
tcpdump -i eth0 -w /captures/mainnet/capture_001_mainnet.pcap \
  host <NODE_B_PUBLIC_IP> and port 8333
```

Detach: `Ctrl+A D`

### 6.4 Start all-peers capture (simulates ISP view)

```bash
# On Server 1 — capture ALL Bitcoin traffic on port 8333
screen -S allpeers001
tcpdump -i eth0 -w /captures/mainnet/capture_001_allpeers.pcap port 8333
```

Detach: `Ctrl+A D`

### 6.5 Start RTT measurement

```bash
# On Server 2 — ping Node A's public IP for the full duration
screen -S ping001
ping -i 1 <NODE_A_PUBLIC_IP> | tee /tmp/ping_capture001.txt
```

Detach: `Ctrl+A D`

### 6.6 Wait 120 minutes

The capture window should contain at least 10–12 blocks (Bitcoin averages one
block per 10 minutes). For a statistically stronger result, run for 8+ hours.

### 6.7 Stop all captures

```bash
# Stop tcpdump sessions
screen -r capture001    # then Ctrl+C
screen -r allpeers001   # then Ctrl+C
screen -r ping001       # then Ctrl+C

# Copy the debug log for the capture window
cp /nodes/nodeA/debug.log /captures/mainnet/debug_nodeA_capture001.log
```

---

## Part 7 — Capture 002: Blocksonly (120 Minutes)

### 7.1 Reconfigure Node B to blocksonly mode

Edit `/nodes/nodeB/bitcoin.conf` and add:

```ini
blocksonly=1
```

### 7.2 Restart Node B

```bash
# On Server 2
bitcoin-cli -datadir=/nodes/nodeB stop
sleep 5
bitcoind -datadir=/nodes/nodeB -daemon
```

Wait for Node B to reconnect to Node A and sync to chain tip.

### 7.3 Repeat the capture procedure from Part 6

```bash
# On Server 1
screen -S capture002
tcpdump -i eth0 -w /captures/mainnet/capture_002_mainnet.pcap \
  host <NODE_B_PUBLIC_IP> and port 8333

screen -S allpeers002
tcpdump -i eth0 -w /captures/mainnet/capture_002_allpeers.pcap port 8333

# On Server 2
screen -S ping002
ping -i 1 <NODE_A_PUBLIC_IP> | tee /tmp/ping_capture002.txt
```

Wait 120+ minutes, then stop all captures and copy the debug log:

```bash
cp /nodes/nodeA/debug.log /captures/mainnet/debug_nodeA_capture002.log
```

---

## Part 8 — Transfer Files to Analysis Machine

Copy the captures and debug logs to your local machine or a dedicated analysis server.

```bash
# From your local machine
scp root@<SERVER1_PUBLIC_IP>:/captures/mainnet/capture_bip324_handshake.pcap ./captures/mainnet/
scp root@<SERVER1_PUBLIC_IP>:/captures/mainnet/capture_001_mainnet.pcap ./captures/mainnet/
scp root@<SERVER1_PUBLIC_IP>:/captures/mainnet/capture_002_mainnet.pcap ./captures/mainnet/
scp root@<SERVER1_PUBLIC_IP>:/captures/mainnet/debug_nodeA_capture001.log ./captures/mainnet/
scp root@<SERVER1_PUBLIC_IP>:/captures/mainnet/debug_nodeA_capture002.log ./captures/mainnet/
```

> The all-peers captures (74 MB and 157 MB) are large. Transfer them only if you
> intend to run the all-peers analysis.

---

## Part 9 — Run the Analysis

### 9.1 Set up the Python environment

```bash
cd /path/to/this/repo
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 9.2 Run the handshake fingerprint analysis

```bash
python3 analysis/analyze_handshake.py \
  --pcap captures/mainnet/capture_bip324_handshake.pcap \
  --node-a-ip <NODE_A_PUBLIC_IP> \
  --node-b-ip <NODE_B_PUBLIC_IP>
```

Expected output: `analysis/analysis_handshake_bip324.txt`

### 9.3 Run the event visibility analysis — Capture 001

```bash
python3 analysis/analyze_capture.py \
  --pcap captures/mainnet/capture_001_mainnet.pcap \
  --debug-log captures/mainnet/debug_nodeA_capture001.log \
  --output analysis/analysis_001_mainnet.txt
```

### 9.4 Run the event visibility analysis — Capture 002

```bash
python3 analysis/analyze_capture.py \
  --pcap captures/mainnet/capture_002_mainnet.pcap \
  --debug-log captures/mainnet/debug_nodeA_capture002.log \
  --output analysis/analysis_002_mainnet.txt
```

---

## Common Problems and Fixes

| Problem | Cause | Fix |
|---------|-------|-----|
| `bitcoin-cli stop` gives "couldn't connect to server" | bitcoind not running | Check with `ps aux | grep bitcoind` |
| capture pcap file is 0 bytes | Node B disconnected before capture started | Restart Node B and retry tcpdump |
| Node B not connecting to Node A | Firewall blocking port 8333 | `sudo ufw allow 8333/tcp` on Server 1 |
| rsync fails with permission denied | SSH key not on Server 1 | Copy your public key: `ssh-copy-id root@SERVER1` |
| tshark not found | Not installed | `sudo apt install tshark` |
| Analysis script outputs wrong peer events | Wrong peer ID used | Re-check peer ID with `getpeerinfo` at capture start |
| `capture_002_mainnet.pcap` shows no block events | blocksonly=1 not applied | Confirm config, restart Node B, verify with `getpeerinfo` |

---

## Expected Results Summary

After running both captures and analysis scripts, your output files should show
approximately:

| Metric | Full-Relay | Blocksonly |
|--------|-----------|------------|
| Avg bytes/sec | ~2,100–2,200 | ~40–50 |
| Blocks visible (r > 2x) | ~75–85% | ~90–95% |
| Large tx visible | ~15–20% | ~0% |
| addr visible | ~0% | N/A |

Exact numbers will differ from the reference results in `results/` because
Bitcoin block timing and mempool state vary between runs.

---

## File Reference

| File | Description |
|------|-------------|
| `analysis/analyze_capture.py` | Main event visibility pipeline |
| `analysis/analyze_handshake.py` | BIP-324 handshake fingerprint analysis |
| `results/analysis_001_mainnet.txt` | Reference output — full-relay capture |
| `results/analysis_002_mainnet.txt` | Reference output — blocksonly capture |
| `results/analysis_handshake_bip324.txt` | Reference output — handshake analysis |
| `captures/mainnet/` | pcap files (see captures/README.md for download links) |
| `Mainnet_research.md` | Full research report with methodology and findings |
