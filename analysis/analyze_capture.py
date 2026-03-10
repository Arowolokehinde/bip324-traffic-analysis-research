"""
Bitcoin P2P Traffic Analysis Script
====================================
Parses a pcap capture file and checks whether the timings of specific
Bitcoin P2P events (blocks, compact blocks, large transactions, getaddr
responses) are visible in the encrypted traffic metadata.

Passive attacker model: observer sees only packet sizes + timestamps.
Content is encrypted (BIP-324). Question: can event timings be identified?

Usage:
    python3 analyze_capture.py [capture_file.pcap] [debug.log]

    If no argument is given, defaults to capture_002.pcap.

Output:
    - Per-second traffic plot with event timing markers
    - Per-event visibility ratios (event second vs rolling baseline)
    - Summary of which event types are detectable from traffic metadata
"""

import sys
import subprocess
import re
import os
from datetime import datetime, timezone

import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.dates as mdates


# File paths

if len(sys.argv) > 1:
    pcap_arg = sys.argv[1]
    if os.path.isabs(pcap_arg) or os.path.exists(pcap_arg):
        PCAP_FILE = os.path.expanduser(pcap_arg)
    else:
        PCAP_FILE = os.path.expanduser(f"~/P2P-traffic-Research/captures/{pcap_arg}")
else:
    PCAP_FILE = os.path.expanduser("~/P2P-traffic-Research/captures/capture_002.pcap")

PCAP_NAME = os.path.basename(PCAP_FILE)

if len(sys.argv) > 2:
    DEBUG_LOG = os.path.expanduser(sys.argv[2])
else:
    DEBUG_LOG = "/nodes/nodeA/debug.log"

OUTPUT_DIR  = os.path.expanduser("~/P2P-traffic-Research/analysis/plots/")
OUTPUT_PLOT = os.path.join(OUTPUT_DIR, f"traffic_vs_blocks_{PCAP_NAME.replace('.pcap', '')}.png")
os.makedirs(OUTPUT_DIR, exist_ok=True)

print(f"Analyzing: {PCAP_FILE}")
print(f"Debug log: {DEBUG_LOG}")


# Step 1: Parse pcap with tshark

print("\nStep 1: Parsing pcap file with tshark...")

result = subprocess.run([
    'tshark', '-r', PCAP_FILE,
    '-T', 'fields',
    '-e', 'frame.time_epoch',
    '-e', 'frame.len'
], capture_output=True, text=True)

if result.returncode != 0:
    print(f"ERROR: tshark failed: {result.stderr}")
    exit(1)

# Build two parallel arrays — avoids N dict allocations
timestamps, sizes = [], []
for line in result.stdout.strip().split('\n'):
    parts = line.strip().split('\t')
    if len(parts) == 2:
        try:
            timestamps.append(float(parts[0]))
            sizes.append(int(parts[1]))
        except ValueError:
            continue

if not timestamps:
    print("ERROR: No packets found in pcap file.")
    exit(1)

print(f"  Found {len(timestamps):,} packets in capture file")

df = pd.DataFrame({'timestamp': timestamps, 'bytes': sizes})
df['time'] = pd.to_datetime(df['timestamp'], unit='s', utc=True)
df = df.set_index('time').sort_index()

traffic_per_minute = df['bytes'].resample('1min').sum()
traffic_per_second = df['bytes'].resample('1s').sum().fillna(0)

tmin = traffic_per_minute.index[0]
tmax = traffic_per_minute.index[-1]

print(f"  Capture start:  {df.index[0].strftime('%Y-%m-%d %H:%M:%S UTC')}")
print(f"  Capture end:    {df.index[-1].strftime('%Y-%m-%d %H:%M:%S UTC')}")
print(f"  Total duration: {(df.index[-1] - df.index[0]).total_seconds() / 60:.1f} minutes")


# Step 2: Parse debug log — single pass, precompiled regex, early exit
# Extracts: block arrivals, compact blocks, addr dumps, large transactions

print("\nStep 2: Extracting events from debug log...")

LARGE_TX_BYTES = 10000  # bytes — threshold for "large" individual transaction

# Precompile both patterns once
RE_UPDATETIP = re.compile(
    r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z) UpdateTip:.*height=(\d+).*progress=1\.'
)
RE_RECV = re.compile(
    r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z).*received: (\w+) \((\d+) bytes\)'
)

block_times,    block_heights  = [], []
cmpctblock_times               = []
addrv2_times,   addrv2_sizes   = [], []
large_tx_times, large_tx_sizes = [], []

def parse_ts(ts_str):
    return pd.Timestamp(
        datetime.strptime(ts_str, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=timezone.utc)
    )

past_window_count = 0

with open(DEBUG_LOG, 'r') as f:
    for line in f:
        
        if len(line) < 20 or line[4] != '-':
            continue

        m = RE_UPDATETIP.search(line)
        if m:
            ts = parse_ts(m.group(1))
            if ts < tmin:
                continue
            if ts > tmax:
                past_window_count += 1
                if past_window_count > 50:
                    break
                continue
            block_times.append(ts)
            block_heights.append(int(m.group(2)))
            past_window_count = 0
            continue

        m = RE_RECV.search(line)
        if m:
            ts = parse_ts(m.group(1))
            if ts < tmin:
                continue
            if ts > tmax:
                past_window_count += 1
                if past_window_count > 50:
                    break
                continue
            past_window_count = 0
            msg_type = m.group(2)
            size     = int(m.group(3))

            if msg_type == 'cmpctblock':
                cmpctblock_times.append(ts)
            elif msg_type in ('addr', 'addrv2') and size > 1000:
                addrv2_times.append(ts)
                addrv2_sizes.append(size)
            elif msg_type == 'tx' and size > LARGE_TX_BYTES:
                large_tx_times.append(ts)
                large_tx_sizes.append(size)

print(f"  Blocks in capture:              {len(block_times)}")
for bt, bh in zip(block_times, block_heights):
    print(f"    Block {bh}: {bt.strftime('%H:%M:%S UTC')}")
print(f"  Compact blocks received:        {len(cmpctblock_times)}")
print(f"  Large addr/addrv2 dumps (>1KB): {len(addrv2_times)}")
print(f"  Large transactions (>{LARGE_TX_BYTES//1000}KB):    {len(large_tx_times)}")


# Step 3: Event visibility analysis

print("\nStep 3: Computing event visibility (event second vs rolling baseline)...")

BASELINE_WINDOW = 60  # seconds on each side of event to compute baseline

def visibility_ratio(event_times, traffic_series, window=BASELINE_WINDOW):
    """
    For each event at time T, compute:
        ratio = traffic[T] / mean(traffic[T-window : T+window], excluding T)
    ratio >> 1 means the event second is visibly higher than surrounding baseline.
    ratio ≈ 1 means the event is indistinguishable from background traffic.
    Returns list of (timestamp, event_bytes, baseline_bytes, ratio).
    """
    results = []
    for ts in event_times:
        event_sec  = ts.floor('1s')
        event_val  = traffic_series.get(event_sec, 0)

        window_start = event_sec - pd.Timedelta(seconds=window)
        window_end   = event_sec + pd.Timedelta(seconds=window)
        baseline     = traffic_series[window_start:window_end].drop(
                           labels=[event_sec], errors='ignore'
                       )
        baseline_mean = baseline.mean() if len(baseline) > 0 else 0
        ratio = event_val / baseline_mean if baseline_mean > 0 else float('inf')
        results.append((ts, event_val, baseline_mean, ratio))
    return results

block_visibility    = visibility_ratio(block_times,     traffic_per_second)
cmpct_visibility    = visibility_ratio(cmpctblock_times, traffic_per_second)
addrv2_visibility   = visibility_ratio(addrv2_times,    traffic_per_second)
large_tx_visibility = visibility_ratio(large_tx_times,  traffic_per_second)

def print_visibility(label, results):
    if not results:
        return
    ratios = [r[3] for r in results if r[3] != float('inf')]
    avg_ratio = sum(ratios) / len(ratios) if ratios else 0
    visible   = sum(1 for r in results if r[3] > 2.0)
    print(f"  {label}:")
    print(f"    Occurrences:        {len(results)}")
    print(f"    Avg visibility r:   {avg_ratio:.2f}x baseline")
    print(f"    Clearly visible (>2x baseline): {visible}/{len(results)}")

print_visibility("Block arrivals (UpdateTip)",      block_visibility)
print_visibility("Compact blocks (cmpctblock)",     cmpct_visibility)
print_visibility("addr/addrv2 dumps (>1KB)",        addrv2_visibility)
print_visibility(f"Large transactions (>{LARGE_TX_BYTES//1000}KB)", large_tx_visibility)

# Also compute compact block → UpdateTip delay (BIP-152 reconstruction time)
if cmpctblock_times and block_times:
    print(f"\n  Compact block → UpdateTip delay (block reconstruction time):")
    for bt, bh in zip(block_times, block_heights):
        # Find the closest cmpctblock that preceded this UpdateTip
        preceding = [ct for ct in cmpctblock_times if ct <= bt]
        if preceding:
            closest = max(preceding)
            delay_ms = (bt - closest).total_seconds() * 1000
            print(f"    Block {bh}: {delay_ms:.0f} ms reconstruction time")


# Step 4: Generate the plot

print("\nStep 4: Generating traffic plot...")

if 'mainnet' in PCAP_NAME.lower():
    network_label = 'Mainnet'
elif 'signet' in PCAP_NAME.lower():
    network_label = 'Signet'
elif 'testnet' in PCAP_NAME.lower():
    network_label = 'Testnet'
else:
    network_label = 'Bitcoin'

fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(16, 10), sharex=True)
fig.suptitle(
    f'BIP-324 Encrypted Bitcoin P2P Traffic Analysis — Passive Attacker View\n'
    f'{network_label} ({PCAP_NAME})  |  '
    f'Can event timings be identified from encrypted traffic?',
    fontsize=12, fontweight='bold'
)

#  Top: bytes per minute 
ax1.fill_between(traffic_per_minute.index, traffic_per_minute.values,
                 alpha=0.4, color='steelblue')
ax1.plot(traffic_per_minute.index, traffic_per_minute.values,
         color='steelblue', linewidth=1.5, label='Traffic (bytes/min)')
ax1.relim(); ax1.autoscale_view()
ymax = ax1.get_ylim()[1]

# Block arrival labels
for bt, bh in zip(block_times, block_heights):
    ax1.text(bt, ymax * 0.85, f'#{bh}', rotation=90,
             fontsize=8, color='red', ha='right')

# Batch vlines — one call per event type, not one call per event
def add_vlines(ax, times, color, alpha, lw, ls, label):
    if not times:
        return
    xvals = [t.to_pydatetime() for t in times]
    ax.vlines(xvals, ymin=0, ymax=ax.get_ylim()[1],
              colors=color, alpha=alpha, linewidth=lw, linestyles=ls, label=label)

ax1.relim(); ax1.autoscale_view()
add_vlines(ax1, block_times,     'red',    0.8, 2.0, 'dashed',  'Block arrival')
add_vlines(ax1, cmpctblock_times,'orange', 0.6, 1.2, 'dotted',  'Compact block')
add_vlines(ax1, addrv2_times,    'purple', 0.5, 1.0, 'dashdot', 'addr/addrv2 dump')
add_vlines(ax1, large_tx_times,  'green',  0.4, 1.0, 'dotted',  f'Large tx (>{LARGE_TX_BYTES//1000}KB)')

ax1.set_ylabel('Bytes per minute')
ax1.legend(loc='upper left', fontsize=8)
ax1.set_title('bytes/minute — coarse view')
ax1.grid(True, alpha=0.3)

#  Bottom: bytes per second 
ax2.fill_between(traffic_per_second.index, traffic_per_second.values,
                 alpha=0.4, color='darkorange')
ax2.plot(traffic_per_second.index, traffic_per_second.values,
         color='darkorange', linewidth=0.8, label='Traffic (bytes/sec)')
ax2.relim(); ax2.autoscale_view()

add_vlines(ax2, block_times,     'red',    0.8, 2.0, 'dashed',  'Block arrival')
add_vlines(ax2, cmpctblock_times,'orange', 0.6, 1.2, 'dotted',  'Compact block')
add_vlines(ax2, addrv2_times,    'purple', 0.5, 1.0, 'dashdot', 'addr/addrv2 dump')
add_vlines(ax2, large_tx_times,  'green',  0.4, 1.0, 'dotted',  f'Large tx (>{LARGE_TX_BYTES//1000}KB)')

ax2.set_ylabel('Bytes per second')
ax2.set_xlabel('Time (UTC)')
ax2.legend(loc='upper left', fontsize=8)
ax2.set_title('bytes/second — timing precision view')
ax2.grid(True, alpha=0.3)

ax2.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
ax2.xaxis.set_major_locator(mdates.MinuteLocator(interval=5))
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig(OUTPUT_PLOT, dpi=150, bbox_inches='tight')
print(f"  Plot saved to: {OUTPUT_PLOT}")


# Step 5: Summary

print("\n" + "="*65)
print("SUMMARY — EVENT TIMING VISIBILITY ANALYSIS")
print("="*65)
print(f"Capture file:            {PCAP_NAME}")
print(f"Duration:                {(df.index[-1] - df.index[0]).total_seconds() / 60:.1f} minutes")
print(f"Total packets:           {len(timestamps):,}")
print(f"Total bytes:             {df['bytes'].sum():,}")
print(f"Avg bytes/sec:           {traffic_per_second.mean():.1f}")
print(f"Max bytes/sec:           {traffic_per_second.max():.0f}")
print()

def summarize_visibility(label, results, avg_label=True):
    if not results:
        print(f"{label}: no events found in capture window")
        return
    print(f"{label} ({len(results)} events):")
    print(f"  {'Time':<12} {'Bytes@event':<14} {'Baseline mean':<16} {'Ratio':<8} {'Visible?'}")
    print(f"  {'-'*60}")
    for ts, ev, bl, ratio in results:
        visible = "YES" if ratio > 2.0 else "no"
        ratio_str = f"{ratio:.1f}x" if ratio != float('inf') else "inf"
        print(f"  {ts.strftime('%H:%M:%S'):<12} {ev:<14.0f} {bl:<16.1f} {ratio_str:<8} {visible}")
    if avg_label:
        finite = [r[3] for r in results if r[3] != float('inf')]
        if finite:
            print(f"  Average ratio: {sum(finite)/len(finite):.2f}x  |  "
                  f"Visible (>2x): {sum(1 for r in finite if r > 2.0)}/{len(results)}")
    print()

summarize_visibility("Block arrivals (UpdateTip)",     block_visibility)
summarize_visibility("Compact blocks (cmpctblock)",    cmpct_visibility)
summarize_visibility("addr/addrv2 dumps (>1KB)",       addrv2_visibility)
summarize_visibility(f"Large tx (>{LARGE_TX_BYTES//1000}KB)", large_tx_visibility)

print("Top 5 busiest seconds:")
print(f"  {'Time':<12} {'Bytes/sec':<14} {'Event at this second?'}")
print(f"  {'-'*50}")
block_sec_set   = {bt.floor('1s') for bt in block_times}
cmpct_sec_set   = {ct.floor('1s') for ct in cmpctblock_times}
addrv2_sec_set  = {at.floor('1s') for at in addrv2_times}
for ts, val in traffic_per_second.nlargest(5).items():
    events = []
    if ts in block_sec_set:   events.append('Block')
    if ts in cmpct_sec_set:   events.append('Cmpctblock')
    if ts in addrv2_sec_set:  events.append('addr dump')
    label = ', '.join(events) if events else 'None'
    print(f"  {ts.strftime('%H:%M:%S'):<12} {val:<14.0f} {label}")

print()
print("NOTE: ratio > 2x means an attacker observing only encrypted traffic")
print("metadata could likely identify when that event occurred.")
print("ratio ≈ 1x means the event is indistinguishable from background.")
print("="*65)
