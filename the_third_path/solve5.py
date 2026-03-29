from scapy.all import rdpcap, DNS, DNSQR, IP
import struct
import re

packets = rdpcap("capture_og0oXNg.pcap")
dns_packets = [pkt for pkt in packets if pkt.haslayer(DNS) and pkt.haslayer(DNSQR)]

timestamps = [float(pkt.time) for pkt in dns_packets]
deltas = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

with open("memory_IcOZWTs.dmp", "rb") as f:
    mem_data = f.read()

payload_key = bytes.fromhex("f184376b295ff909723748c7865e7e623ba4bb0bbde13f3c131faafdaff3aef6651197dc76d110067dc3d022a90af7dbf36e198543bfe7cc75c9ce329036ddba")

# delta units in 1/32 second = integer
delta_units = [round(d * 32) for d in deltas]
BASE = 259
dev_units = [BASE - u for u in delta_units]

# Key observations:
# - 1912 packets have deviation 0 (normal heartbeat)
# - 1089 packets have non-zero deviation
# - Deviations range from -16 to 255

# NEW THEORY: What if deviation directly encodes a byte VALUE
# and zeros are ignored (or separators)?
# There are 1089 non-zero deviations -> about 1089 bytes

# Let's take non-zero deviations as bytes
non_zero_devs = [d for d in dev_units if d != 0]
print(f"Non-zero deviations count: {len(non_zero_devs)}")
print(f"Min: {min(non_zero_devs)}, Max: {max(non_zero_devs)}")

# There's a problem: some are negative (dev > 259 means delta was negative - impossible)
# Actually, dev = 259 - delta_unit, so if delta_unit > 259, dev < 0
# The negative dev = -16 means delta = 259 + 16 = 275 units = 8.59375s (the 8.6s delta)
# This is the FIRST packet (delta 0, pkt 0 -> pkt 1)

# Filter to valid byte range [0, 255]
valid_bytes = [d for d in non_zero_devs if 0 <= d <= 255]
print(f"Valid byte-range deviations: {len(valid_bytes)}")
print(f"First 50: {valid_bytes[:50]}")

# Convert to bytes
byte_data = bytes(valid_bytes)
print(f"\nAs hex: {byte_data[:100].hex()}")
print(f"As ASCII: {byte_data[:100]}")
ascii_s = re.findall(rb'[\x20-\x7e]{4,}', byte_data)
print(f"ASCII strings: {ascii_s[:30]}")

# XOR with payload key
xored = bytes(byte_data[i] ^ payload_key[i % len(payload_key)] for i in range(len(byte_data)))
print(f"\nXOR with payload key:")
print(f"As hex: {xored[:100].hex()}")
ascii_s = re.findall(rb'[\x20-\x7e]{4,}', xored)
print(f"ASCII strings: {ascii_s[:30]}")
if b'MythX' in xored:
    pos = xored.find(b'MythX')
    print(f"FOUND MythX at {pos}: {xored[pos:pos+80]}")

# ============================================
# MAJOR INSIGHT: The challenge says "heartbeat bridging network and RAM"
# The timing deviations tell us WHERE to look in the memory dump
# Each deviation is an offset/index into memory
# 
# But the memory is 2MB and deviations are max 255...
# So we need a scaling factor
#
# OR: maybe we need to combine the timing with something else
# Like: the index of each packet PLUS the deviation
# ============================================

# Let me try: use the INDEX of the non-standard packet as a memory offset
print("\n\n=== INDEX-BASED MEMORY EXTRACTION ===")
non_std_positions = [(i, dev_units[i]) for i in range(len(dev_units)) if dev_units[i] != 0]
print(f"First 20 (position, deviation): {non_std_positions[:20]}")

# Theory: packet_position * some_scale = memory offset to read
# The byte we read from memory at that offset tells us the flag
for scale in [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 700, 1024, 2048]:
    extracted = bytearray()
    for pos, dev in non_std_positions:
        offset = pos * scale
        if offset < len(mem_data):
            extracted.append(mem_data[offset])
    ascii_s = re.findall(rb'[\x20-\x7e]{6,}', bytes(extracted))
    if ascii_s:
        print(f"  scale={scale}: {ascii_s[:5]}")
    # Also XOR the extracted bytes with the deviation value
    extracted_xor = bytearray()
    for pos, dev in non_std_positions:
        offset = pos * scale
        if offset < len(mem_data) and 0 <= dev <= 255:
            extracted_xor.append(mem_data[offset] ^ dev)
    ascii_s = re.findall(rb'[\x20-\x7e]{6,}', bytes(extracted_xor))
    if ascii_s:
        print(f"  scale={scale} XOR dev: {ascii_s[:5]}")

# ============================================
# Let me try a completely different approach:
# What if the CUMULATIVE sum of deviations gives us memory offsets?
# ============================================
print("\n\n=== CUMULATIVE DEVIATION AS OFFSET ===")
cum_offset = 0
extracted = bytearray()
for d in dev_units:
    if d != 0:
        cum_offset += d
        if 0 <= cum_offset < len(mem_data):
            extracted.append(mem_data[cum_offset])
print(f"Extracted length: {len(extracted)}")
print(f"First 50 hex: {bytes(extracted[:50]).hex()}")
ascii_s = re.findall(rb'[\x20-\x7e]{4,}', bytes(extracted))
print(f"ASCII: {ascii_s[:20]}")

# ============================================
# Another approach: the absolute timestamp encodes memory offset
# ts = 1672531200 + offset * 8.09375
# The actual timestamp may deviate, and the difference from expected  
# tells us what byte to use from memory
# ============================================
print("\n\n=== EXPECTED vs ACTUAL TIMESTAMP ===")
start_ts = timestamps[0]
expected_ts = [start_ts + i * 8.09375 for i in range(len(timestamps))]
ts_diffs = [timestamps[i] - expected_ts[i] for i in range(len(timestamps))]
print(f"Timestamp diffs from expected (first 30): {[round(d, 5) for d in ts_diffs[:30]]}")

# Let me compute this as cumulative drift
print(f"\nCumulative drift (round to 1/32):")
drifts_units = [round(d * 32) for d in ts_diffs]
print(f"First 50 drift units: {drifts_units[:50]}")

# These drifts accumulate! The drift encodes a message
# When drift changes, it's data
drift_changes = [drifts_units[i+1] - drifts_units[i] for i in range(len(drifts_units)-1)]
print(f"\nDrift changes (first 50): {drift_changes[:50]}")
# This is just the deviations again...

# ============================================
# OK let me try the simplest thing:
# The challenge says "bridge network and RAM"
# Network = timing deviation
# RAM = memory byte
#
# Maybe: XOR(deviation, memory[packet_index]) = flag character?
# ============================================
print("\n\n=== XOR(deviation, memory[index]) for each non-std packet ===")
for mem_scale in [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 694, 698, 699, 700]:
    extracted = bytearray()
    for pos, dev in non_std_positions:
        offset = pos * mem_scale
        if offset < len(mem_data) and 0 <= dev <= 255:
            extracted.append(mem_data[offset] ^ (dev & 0xFF))
    ascii_s = re.findall(rb'[\x20-\x7e]{6,}', bytes(extracted))
    if ascii_s:
        print(f"  mem_scale={mem_scale}: {ascii_s[:5]}")

# ============================================
# What if the deviation value IS the memory offset to read?
# deviation * some_scale = offset
# And we read one byte from memory at that offset
# ============================================
print("\n\n=== DEVIATION VALUE AS MEMORY OFFSET ===")
for scale in [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192]:
    extracted = bytearray()
    for _, dev in non_std_positions:
        offset = abs(dev) * scale
        if offset < len(mem_data):
            extracted.append(mem_data[offset])
    ascii_s = re.findall(rb'[\x20-\x7e]{6,}', bytes(extracted))
    if ascii_s:
        print(f"  dev*{scale}: {ascii_s[:5]}")

# ============================================
# What about: each delta (including base) contributes to reconstruction
# Use ALL deltas to index into memory?
# ============================================
print("\n\n=== ALL DELTA UNITS AS SEQUENTIAL BYTES (raw) ===")  
# Each delta unit is 0-275, maybe mod 256
raw = bytes([u % 256 for u in delta_units])
print(f"First 100: {raw[:100].hex()}")
ascii_s = re.findall(rb'[\x20-\x7e]{6,}', raw)
print(f"ASCII: {ascii_s[:20]}")

# XOR with memory
print("\n=== XOR(delta_units, memory) ===")
for offset in range(0, 10000, 512):
    chunk = mem_data[offset:offset+len(raw)]
    if len(chunk) < len(raw):
        break
    xored = bytes(raw[i] ^ chunk[i] for i in range(len(chunk)))
    ascii_s = re.findall(rb'[\x20-\x7e]{8,}', xored)
    if ascii_s:
        print(f"  mem offset {offset}: {ascii_s[:5]}")

# ============================================
# FINAL IDEAS: What if the memory dump has a specific structure?
# Let me look for non-random regions or headers in the memory dump
# ============================================
print("\n\n=== MEMORY DUMP STRUCTURE SCAN ===")
# Look for common file signatures
sigs = {
    b'PK': 'ZIP', b'\x50\x4b\x03\x04': 'ZIP_full',
    b'\x89PNG': 'PNG', b'\xff\xd8\xff': 'JPEG',
    b'MZ': 'PE/EXE', b'\x7fELF': 'ELF',
    b'BM': 'BMP', b'GIF8': 'GIF',
    b'Salted__': 'OpenSSL_enc',
    b'MYTHX': 'MYTHX', b'mythx': 'mythx',
}
for sig, name in sigs.items():
    positions = [m.start() for m in re.finditer(re.escape(sig), mem_data)]
    if positions:
        print(f"  {name}: {positions[:10]}")

# Look for all printable strings > 10 chars
long_strings = re.findall(rb'[\x20-\x7e]{10,}', mem_data)
print(f"\nLong strings (len>=10): {len(long_strings)}")
for s in long_strings[:20]:
    print(f"  {s}")

# Look for the area around the decoy flag more carefully
decoy_pos = 1688900
print(f"\n\nMemory around decoy flag (offset {decoy_pos}):")
for start in range(decoy_pos - 500, decoy_pos + 500, 50):
    chunk = mem_data[start:start+50]
    printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
    print(f"  {start:#010x}: {printable}")
