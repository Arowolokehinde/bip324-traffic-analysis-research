"""
BIP-324 Handshake Fingerprint Analysis
=======================================
Parses a short handshake capture pcap and analyses the packet size
sequence and timing to determine whether the BIP-324 / ElligatorSwift
connection establishment is distinguishable from other encrypted protocols
(TLS 1.3, SSH).

Passive attacker model: observer sees only packet sizes, timing, and IP
direction. Content is encrypted or pseudorandom.

Usage:
    python3 analyze_handshake.py <handshake.pcap>

Output:
    - Packet-by-packet table of the handshake sequence
    - Size and timing metrics (first packet sizes, symmetry ratio, duration)
    - Protocol comparison table (BIP-324 vs TLS 1.3 vs SSH)
    - Fingerprinting verdict

Background:
    BIP-324 handshake structure (ElligatorSwift key exchange):
      Initiator → Responder:  64-byte key  +  0–4095 bytes garbage  +  16-byte terminator
                              = 80 to 4,175 bytes in first data burst (random length)
      Responder → Initiator:  same structure
    This is SYMMETRIC: both sides send similar random-sized initial data.

    TLS 1.3 handshake structure:
      Initiator → Responder:  ClientHello  (~200–600 bytes)
      Responder → Initiator:  ServerHello + Certificate + CertVerify + Finished
                              (~1,500–10,000 bytes)
    This is ASYMMETRIC: responder sends 5–20x more data than initiator.

    The symmetry ratio (responder first / initiator first) is the primary
    distinguishing metric between these two protocols.
"""

import sys
import subprocess
import os

# ─────────────────────────────────────────
# Input
# ─────────────────────────────────────────
if len(sys.argv) < 2:
    print("Usage: python3 analyze_handshake.py <handshake.pcap>")
    sys.exit(1)

PCAP_FILE = os.path.expanduser(sys.argv[1])

if not os.path.exists(PCAP_FILE):
    print(f"ERROR: File not found: {PCAP_FILE}")
    sys.exit(1)

print(f"Analyzing handshake capture: {PCAP_FILE}")

# ─────────────────────────────────────────
# Step 1: Parse all packets with tshark
# Extract: frame number, relative time, frame length, src/dst IPs,
#          TCP payload length, SYN flag, ACK flag
# ─────────────────────────────────────────
print("\nStep 1: Parsing pcap with tshark...")

result = subprocess.run([
    'tshark', '-r', PCAP_FILE,
    '-T', 'fields',
    '-e', 'frame.number',
    '-e', 'frame.time_relative',
    '-e', 'frame.len',
    '-e', 'ip.src',
    '-e', 'ip.dst',
    '-e', 'tcp.len',
], capture_output=True, text=True)

if result.returncode != 0:
    print(f"ERROR: tshark failed: {result.stderr}")
    sys.exit(1)

packets = []
for line in result.stdout.strip().split('\n'):
    parts = line.strip().split('\t')
    if len(parts) < 6:
        continue
    try:
        packets.append({
            'num':       int(parts[0]),
            'time':      float(parts[1]),
            'frame_len': int(parts[2]),
            'src':       parts[3],
            'dst':       parts[4],
            'tcp_len':   int(parts[5]) if parts[5].strip() else 0,
        })
    except (ValueError, IndexError):
        continue

if not packets:
    print("ERROR: No packets parsed. Is the pcap a valid TCP capture?")
    sys.exit(1)

print(f"  Total packets in capture: {len(packets)}")

# ─────────────────────────────────────────
# Step 2: Identify the TCP connection initiator
# Use a tshark display filter to find the SYN packet (SYN=1, ACK=0).
# This is more reliable than parsing raw flag fields, which tshark can
# output inconsistently across versions.
# ─────────────────────────────────────────
syn_result = subprocess.run([
    'tshark', '-r', PCAP_FILE,
    '-T', 'fields',
    '-e', 'ip.src',
    '-e', 'ip.dst',
    '-Y', 'tcp.flags.syn == 1 && tcp.flags.ack == 0',
], capture_output=True, text=True)

initiator_ip = None
responder_ip = None

for line in syn_result.stdout.strip().split('\n'):
    parts = line.strip().split('\t')
    if len(parts) >= 2 and parts[0] and parts[1]:
        initiator_ip = parts[0]
        responder_ip = parts[1]
        break

if not initiator_ip:
    # Fall back to first data packet's source if no SYN found
    print("  WARNING: No TCP SYN found — assuming first src IP is initiator")
    initiator_ip = packets[0]['src']
    responder_ip = packets[0]['dst']
else:
    print("  TCP SYN confirmed — initiator identified from SYN packet")

print(f"  Initiator (Node B): {initiator_ip}")
print(f"  Responder (Node A): {responder_ip}")

# ─────────────────────────────────────────
# Step 3: Separate data-bearing packets (tcp.len > 0)
# Pure ACKs (tcp.len == 0) carry no application data and are excluded.
# TCP SYN/SYN-ACK also have tcp.len == 0.
# ─────────────────────────────────────────
data_packets   = [p for p in packets if p['tcp_len'] > 0]
from_initiator = [p for p in data_packets if p['src'] == initiator_ip]
from_responder = [p for p in data_packets if p['src'] == responder_ip]

# ─────────────────────────────────────────
# Step 4: Print packet sequence table
# ─────────────────────────────────────────
print()
print("=" * 72)
print("HANDSHAKE PACKET SEQUENCE  (data packets only, tcp.len > 0)")
print("=" * 72)
print(f"  {'Pkt#':<6} {'Time(s)':<10} {'Direction':<26} {'Frame':>8} {'TCP payload':>12}")
print(f"  {'-' * 66}")

for p in data_packets:
    if p['src'] == initiator_ip:
        direction = f"Init → Resp  ({initiator_ip})"
    else:
        direction = f"Resp → Init  ({responder_ip})"
    print(f"  {p['num']:<6} {p['time']:<10.4f} {direction:<40} {p['frame_len']:>8} {p['tcp_len']:>12}")

# ─────────────────────────────────────────
# Step 5: Compute handshake metrics
# ─────────────────────────────────────────
init_first_tcp  = from_initiator[0]['tcp_len']   if from_initiator else None
resp_first_tcp  = from_responder[0]['tcp_len']   if from_responder else None
init_first_frm  = from_initiator[0]['frame_len'] if from_initiator else None
resp_first_frm  = from_responder[0]['frame_len'] if from_responder else None

init_total_bytes = sum(p['tcp_len'] for p in from_initiator)
resp_total_bytes = sum(p['tcp_len'] for p in from_responder)

all_times            = [p['time'] for p in data_packets]
handshake_duration_ms = (max(all_times) - min(all_times)) * 1000 if all_times else 0

symmetry_ratio = (resp_first_tcp / init_first_tcp
                  if (init_first_tcp and resp_first_tcp) else None)

# ─────────────────────────────────────────
# Step 6: Print metrics
# ─────────────────────────────────────────
print()
print("=" * 72)
print("HANDSHAKE METRICS")
print("=" * 72)
print(f"  Data packets total:              {len(data_packets)}")
print(f"  Data packets from initiator:     {len(from_initiator)}")
print(f"  Data packets from responder:     {len(from_responder)}")
print()
print(f"  First initiator packet (TCP):    {init_first_tcp} bytes   "
      f"(frame: {init_first_frm} bytes incl. headers)")
print(f"  First responder packet (TCP):    {resp_first_tcp} bytes   "
      f"(frame: {resp_first_frm} bytes incl. headers)")
if symmetry_ratio is not None:
    print(f"  Symmetry ratio (resp / init):    {symmetry_ratio:.2f}x")
print()
print(f"  Total bytes from initiator:      {init_total_bytes}")
print(f"  Total bytes from responder:      {resp_total_bytes}")
print(f"  Duration (first to last pkt):    {handshake_duration_ms:.1f} ms")

# ─────────────────────────────────────────
# Step 7: Protocol fingerprint comparison
# ─────────────────────────────────────────
# Reference ranges are based on protocol specifications:
#   BIP-324: https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki
#     Initiator sends: 64 (ElligatorSwift key) + 0–4095 (garbage) + 16 (terminator)
#     Range: 80–4175 bytes. Responder sends same structure.
#   TLS 1.3: RFC 8446
#     ClientHello: typically 200–600 bytes
#     ServerHello + EncryptedExtensions + Certificate + CertVerify + Finished:
#     typically 1500–10000 bytes (certificate chain is the bulk)
#   SSH: RFC 4253
#     First packets are plaintext version banners (~22 bytes each), then key exchange.
#     Immediately identifiable by plaintext content.

PROTOCOLS = {
    'BIP-324 / ElligatorSwift (expected)': {
        'init_range':    (80,  4175),
        'resp_range':    (80,  4175),
        'ratio_range':   (0.02, 50.0),
        'notes': [
            'Both sides send random-sized initial data (garbage padding).',
            'First packet size: 64-byte key + 0–4095 random bytes + 16-byte terminator.',
            'Symmetric by design — ratio ≈ 1x (with wide random variance).',
            'Indistinguishable from obfs4 by these metrics alone.',
        ],
    },
    'TLS 1.3 (expected)': {
        'init_range':    (200,  600),
        'resp_range':    (1500, 10000),
        'ratio_range':   (3.0,  50.0),
        'ratio_required': True,   # asymmetric ratio IS the defining TLS 1.3 feature
        'notes': [
            'ClientHello: ~200–600 bytes (ciphers, extensions, SNI).',
            'Server response: ServerHello + cert chain + Finished (~1.5–10 KB).',
            'Highly ASYMMETRIC — responder sends 5–20x more data than initiator.',
            'Ratio >> 1 is the primary TLS fingerprint.',
        ],
    },
    'SSH (expected)': {
        'init_range':    (15, 55),
        'resp_range':    (15, 55),
        'ratio_range':   (0.5, 2.0),
        'notes': [
            'First packets are plaintext version banners (~22 bytes each).',
            'Example: "SSH-2.0-OpenSSH_9.0\\r\\n"',
            'Immediately identifiable by content (not just size).',
        ],
    },
}

def in_range(val, lo, hi):
    return lo <= val <= hi if val is not None else False

def check_mark(ok):
    return 'MATCH' if ok else 'no   '

print()
print("=" * 72)
print("PROTOCOL FINGERPRINT COMPARISON")
print("=" * 72)

verdicts = []
for proto, spec in PROTOCOLS.items():
    init_ok  = in_range(init_first_tcp,   *spec['init_range'])
    resp_ok  = in_range(resp_first_tcp,   *spec['resp_range'])
    ratio_ok = in_range(symmetry_ratio,   *spec['ratio_range'])
    matched  = sum([init_ok, resp_ok, ratio_ok])
    # If a protocol marks ratio_required=True, a failing ratio means INCONSISTENT
    # regardless of size matches — the ratio IS the defining feature for that protocol.
    if spec.get('ratio_required', False) and not ratio_ok:
        verdict = 'INCONSISTENT'
    else:
        verdict = 'CONSISTENT' if matched >= 2 else ('POSSIBLE' if matched == 1 else 'INCONSISTENT')
    verdicts.append((proto, verdict, matched))

    print(f"\n  {proto}")
    print(f"  {'─' * 60}")
    print(f"    Init first pkt: {spec['init_range'][0]}–{spec['init_range'][1]} bytes"
          f"  →  observed {init_first_tcp}   [{check_mark(init_ok)}]")
    print(f"    Resp first pkt: {spec['resp_range'][0]}–{spec['resp_range'][1]} bytes"
          f"  →  observed {resp_first_tcp}   [{check_mark(resp_ok)}]")
    print(f"    Ratio (r/i):    {spec['ratio_range'][0]:.2f}–{spec['ratio_range'][1]:.1f}x"
          f"         →  observed {f'{symmetry_ratio:.2f}x' if symmetry_ratio else 'N/A'}"
          f"   [{check_mark(ratio_ok)}]")
    print(f"    Criteria met:   {matched}/3   →  Verdict: {verdict}")
    for note in spec['notes']:
        print(f"    Note: {note}")

# ─────────────────────────────────────────
# Step 8: Summary
# ─────────────────────────────────────────
print()
print("=" * 72)
print("SUMMARY")
print("=" * 72)
for proto, verdict, matched in verdicts:
    print(f"  {verdict:<14} {proto}")

print()
print("  KEY INSIGHT:")
print("  The symmetry ratio is the primary discriminator between protocols:")
print("    BIP-324:  ratio ≈ 1x  (both sides send random-sized garbage, by design)")
print("    TLS 1.3:  ratio >> 1x (server sends certificate chain, much larger)")
print("    SSH:      ratio ≈ 1x  (but first bytes are plaintext, trivially identified)")
print()
print("  A ratio near 1.0 with both packets in the 80–4175 byte range is")
print("  consistent with BIP-324 or another pseudorandom-bytestream protocol.")
print("  It does NOT distinguish BIP-324 from obfs4 — both are designed to")
print("  look like random noise with symmetric handshake sizes.")
print()
print("  LIMITATION: A single handshake capture is suggestive but not")
print("  statistically conclusive. Repeat the capture multiple times to")
print("  confirm the pattern across different garbage lengths.")
print("=" * 72)
