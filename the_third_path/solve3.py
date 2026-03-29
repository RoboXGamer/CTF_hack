from scapy.all import rdpcap, DNS, DNSQR, IP
import struct
import re

packets = rdpcap("capture_og0oXNg.pcap")
dns_packets = [pkt for pkt in packets if pkt.haslayer(DNS) and pkt.haslayer(DNSQR)]

timestamps = [float(pkt.time) for pkt in dns_packets]
deltas = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

with open("memory_IcOZWTs.dmp", "rb") as f:
    mem_data = f.read()

# The base heartbeat is ~8.09375s
# Deviations from this encode data
# Let's think about this differently:
# 8.09375 = 8 + 3/32 maybe? Let's check in binary
# 8.09375 ≈ 8 + 0.09375 = 8 + 3/32

# The deltas range from ~0.12 to ~8.6
# What if each delta encodes a byte value?
# Max delta ≈ 8.6, if we divide by some factor...

# Theory 1: delta * 32 = byte value (rounded)
# 8.09375 * 32 = 259 (which is > 255, so maybe base is actually lower)
# No wait, let's think more carefully

# Theory 2: The non-8.09375 deltas encode characters
# Look at the distinct delta clusters more carefully

# Let me quantize deltas to nearest 0.03125 (1/32 second)
print("=== Quantized delta analysis ===")
quantized = [round(d * 32) / 32 for d in deltas]
q_counts = {}
for q in quantized:
    q_counts[q] = q_counts.get(q, 0) + 1

# The "normal" heartbeat
print(f"Most common delta: 8.09375 appears {q_counts.get(8.09375, 0)} times")

# Theory 3: Each delta encodes an index, and we need to look at pairs or groups
# The challenge mentions "subtle heartbeat" - maybe the deviations from 8.09375
# encode memory offsets

# Let me try: deviation from 8.09375, multiplied by some factor, as a memory offset
BASE = 8.09375
print("\n=== Deviation * scale factors ===")
deviations = []
for i, d in enumerate(deltas):
    dev = round(d - BASE, 6)
    if abs(dev) > 0.01:
        deviations.append((i, dev))

print(f"Total deviations: {len(deviations)}")

# What if we take the rounded deviation and multiply by something?
# deviation of -4.0 could mean offset 4*N, deviation of -1.0 means offset N, etc.

# Let's try: the absolute deviation * 32 = byte index
print("\n=== Trying: abs(deviation) * 32 as byte value ===")
dev_values = [abs(round(d * 32)) for _, d in deviations]
print(f"First 50 byte values: {dev_values[:50]}")
print(f"As hex: {bytes(min(v, 255) for v in dev_values[:50]).hex()}")
try:
    text = bytes(min(v, 255) for v in dev_values)
    ascii_s = re.findall(rb'[\x20-\x7e]{4,}', text)
    print(f"ASCII strings: {ascii_s[:20]}")
except Exception as e:
    print(f"Error: {e}")

# Theory 4: Each delta directly encodes a byte
# delta / 8.09375 * 256 or something
print("\n=== Trying: delta * 32 as byte value ===")
byte_vals = [int(round(d * 32)) & 0xFF for d in deltas]
non_normal = [(i, byte_vals[i]) for i in range(len(byte_vals)) if byte_vals[i] != 3]
# 8.09375 * 32 = 259 -> 259 & 0xFF = 3
print(f"Non-normal byte values (first 50): {non_normal[:50]}")

# Theory 5: The deviation encodes the number of seconds to subtract,
# and that gives us a value 0-8 which is a digit or nibble
print("\n=== Trying: int(8 - delta) as nibble ===")
nibbles = []
for i, d in enumerate(deltas):
    val = int(round(8.09375 - d, 1))
    if val != 0:  # only non-zero (i.e., not the normal heartbeat)
        nibbles.append((i, val))
print(f"Nibbles (first 50): {nibbles[:50]}")

# Combine nibbles into bytes
print("Combining pairs of nibbles into bytes:")
nibble_vals = [v for _, v in nibbles]
combined_bytes = []
for j in range(0, len(nibble_vals) - 1, 2):
    byte_val = (nibble_vals[j] << 4) | nibble_vals[j+1]
    combined_bytes.append(byte_val & 0xFF)
print(f"Combined bytes: {bytes(combined_bytes[:50]).hex()}")
ascii_s = re.findall(rb'[\x20-\x7e]{4,}', bytes(combined_bytes))
print(f"ASCII: {ascii_s[:20]}")

# Theory 6: Maybe the position/index of non-standard packets matters
# and we should extract bytes from memory at those positions
print("\n=== Using non-standard packet indices as memory offsets ===")
non_std_indices = [i for i, d in enumerate(deltas) if abs(d - 8.09375) > 0.01]
print(f"Non-standard indices (first 50): {non_std_indices[:50]}")

# Theory 7: Use the timing delta to select a byte from the memory dump
# Delta value -> byte from memory at that offset
print("\n=== Delta as memory offset (scaled) ===")
for scale in [1, 2, 4, 8, 16, 32, 64, 128, 256, 1024]:
    extracted = bytearray()
    for d in deltas:
        offset = int(d * scale)
        if offset < len(mem_data):
            extracted.append(mem_data[offset])
    ascii_s = re.findall(rb'[\x20-\x7e]{6,}', bytes(extracted))
    if ascii_s:
        print(f"  Scale {scale}: {ascii_s[:10]}")

# Theory 8: The gap between non-standard packets encodes something
print("\n=== Gaps between non-standard packets ===")
gaps = [non_std_indices[i+1] - non_std_indices[i] for i in range(len(non_std_indices)-1)]
print(f"Gaps (first 50): {gaps[:50]}")
print(f"Unique gap values: {sorted(set(gaps[:200]))}")

# Theory 9: Combine the position of non-standard packet AND its delta value
# Position = offset, delta deviation = value to XOR or add
print("\n=== Position-based extraction from memory ===")
for strategy_name, positions in [
    ("non_std indices as offsets", non_std_indices[:200]),
    ("non_std indices * 2", [i*2 for i in non_std_indices[:200]]),
]:
    extracted = bytearray()
    for pos in positions:
        if pos < len(mem_data):
            extracted.append(mem_data[pos])
    ascii_s = re.findall(rb'[\x20-\x7e]{4,}', bytes(extracted))
    if ascii_s:
        print(f"  {strategy_name}: {ascii_s[:10]}")

# Theory 10: The fractional part of each delta in units of 1/32
# encodes nibbles (0-15)?
print("\n=== Fractional part in 1/32 units ===")
frac_values = [(d % 1) for d in deltas]
frac_32 = [int(round(f * 32)) for f in frac_values]
frac_counts = {}
for v in frac_32:
    frac_counts[v] = frac_counts.get(v, 0) + 1
print(f"Fractional * 32 distribution: {sorted(frac_counts.items())}")

# Separate integer part and fractional part
int_parts = [int(d) for d in deltas]
frac_parts = [round((d - int(d)) * 1000) for d in deltas]
print(f"\nInteger parts (first 50): {int_parts[:50]}")
print(f"Frac parts *1000 (first 50): {frac_parts[:50]}")

# ========================================
# NEW APPROACH: The memory dump is 2MB of high entropy (encrypted)
# The HTTP payload.bin is 64 bytes
# Maybe we need to use the timing to construct a key to decrypt the memory dump
# Or maybe timing encodes byte values directly

# Let's try: each delta encodes one byte, and the full message is in the
# sequence of ALL 3001 deltas
print("\n\n=== ALL deltas as byte values (various encodings) ===")

# Approach A: (8.09375 - delta) * N = byte value
for N in [32, 64, 128]:
    byte_stream = []
    for d in deltas:
        val = int(round((BASE - d) * N))
        byte_stream.append(val & 0xFF)
    ascii_s = re.findall(rb'[\x20-\x7e]{6,}', bytes(byte_stream))
    if ascii_s:
        print(f"  (BASE-d)*{N}: {ascii_s[:10]}")

# Approach B: only non-BASE deltas, encoded as (BASE - delta) * N
for N in [32, 64, 128]:
    byte_stream = []
    for d in deltas:
        if abs(d - BASE) > 0.01:
            val = int(round((BASE - d) * N))
            byte_stream.append(val & 0xFF)
    ascii_s = re.findall(rb'[\x20-\x7e]{6,}', bytes(byte_stream))
    if ascii_s:
        print(f"  non-base (BASE-d)*{N}: {ascii_s[:10]}")
    # Also try as hex string
    hex_str = ''.join(f'{b:02x}' for b in byte_stream[:100])
    print(f"  non-base (BASE-d)*{N} hex first 100 bytes: {hex_str}")

# Wait - let me reconsider. The pcap timestamps are stored with limited precision
# Let me look at the actual raw timestamp values
print("\n\n=== Raw timestamps ===")
for i in range(min(30, len(timestamps))):
    print(f"  Pkt {i}: ts={timestamps[i]:.6f}")

# Check if timestamps are multiples of some unit
print("\n=== Timestamp modular analysis ===")
ts_mod = [round(t % 8, 4) for t in timestamps]
print(f"ts mod 8 (first 30): {ts_mod[:30]}")

# Perhaps the data is encoded as: each packet's timestamp mod N gives us a value
for mod in [128, 256, 512]:
    vals = [int(t) % mod for t in timestamps]
    byte_stream = bytes(v & 0xFF for v in vals)
    ascii_s = re.findall(rb'[\x20-\x7e]{6,}', byte_stream)
    if ascii_s:
        print(f"  ts mod {mod}: {ascii_s[:10]}")
