from scapy.all import rdpcap, DNS, DNSQR, IP
import struct
import re
import math

packets = rdpcap("capture_og0oXNg.pcap")
dns_packets = [pkt for pkt in packets if pkt.haslayer(DNS) and pkt.haslayer(DNSQR)]

timestamps = [float(pkt.time) for pkt in dns_packets]
deltas = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

with open("memory_IcOZWTs.dmp", "rb") as f:
    mem_data = f.read()

# Key insight: 3002 DNS packets, 2097152 byte memory dump
# 2097152 / 3002 ≈ 699 bytes per packet
# 2097152 = 2^21
# 3001 deltas. 3001 * 7 bits = 21007 bits ≈ 2625 bytes (close to nothing useful)

# Looking at the timing more carefully:
# Base delta = 8.09375 = 8 + 3/32
# The deviations seem to be multiples of 1/32 second (0.03125)

# Let me check: all deltas in units of 1/32 second
print("=== Deltas in 1/32 second units ===")
delta_units = []
for d in deltas:
    unit = round(d * 32)
    delta_units.append(unit)

unit_counts = {}
for u in delta_units:
    unit_counts[u] = unit_counts.get(u, 0) + 1

print(f"Distribution of delta units (delta * 32):")
for k, v in sorted(unit_counts.items()):
    print(f"  {k} ({k/32:.5f}s): {v} times")

# The base is 259 units (8.09375 * 32 = 259)
# Deviations from 259: 
print(f"\nBase unit: 259 (8.09375s)")
dev_units = [259 - u for u in delta_units]
print(f"Deviations from 259 (first 50): {dev_units[:50]}")

# Non-zero deviations
nonzero_devs = [(i, d) for i, d in enumerate(dev_units) if d != 0]
print(f"\nNon-zero deviations: {len(nonzero_devs)}")
print(f"First 30: {nonzero_devs[:30]}")

# What are the unique deviation values?
unique_devs = sorted(set(d for _, d in nonzero_devs))
print(f"\nUnique deviation values: {unique_devs}")
print(f"Number of unique values: {len(unique_devs)}")

# They look like powers of 2! Let me check
print(f"\nAre deviations powers of 2?")
for d in unique_devs:
    if d > 0:
        is_pow2 = (d & (d-1)) == 0
        if is_pow2:
            bit = int(math.log2(d))
            print(f"  {d} = 2^{bit}")
        else:
            print(f"  {d} is NOT a power of 2")

# AMAZING! Let me check this theory - deviations are powers of 2
# This means each non-standard packet encodes ONE BIT position
# The deviation value tells us which bit position (like 2^0=1, 2^1=2, 2^2=4, etc.)
# But 1089 deviations with each encoding a bit... 

# Wait - maybe EACH delta encodes bits via the deviation
# If deviation is a sum of powers of 2, it could encode multiple bits
# deviation to binary gives us bits per delta

print("\n\n=== BINARY ENCODING IN DEVIATIONS ===")
# For each deviation, get the binary representation
# The first 8 bits = 1 byte
all_dev_values = [259 - u for u in delta_units]

# But many deviations are 0 (the base heartbeat)
# Maybe we should include those too - 0 means 0b00000000
# The deviations range from -16 to 259
# Max dev = 259 (when delta=0), which needs 9 bits
# Actually looking at unique_devs, max is 252

# Let me try: each deviation value IS a byte
# But 259-4 = 255 -> 0xFF, and 259-259 = 0 -> 0x00
# So deviation 0 = byte 0, deviation 255 = byte 255
# But deviation 4 = byte 4, etc.
# 
# Actually wait: the deviations I see include negative values
# Let me reconsider

# Let me just try: (259 - delta_in_units) as a byte value directly
print("Treating (259 - delta_unit) as raw byte:")
byte_stream = bytes([max(0, min(255, 259 - u)) for u in delta_units])
print(f"First 100 bytes: {byte_stream[:100].hex()}")
ascii_s = re.findall(rb'[\x20-\x7e]{4,}', byte_stream)
print(f"ASCII strings: {ascii_s[:20]}")

# Check for MythX
if b'MythX' in byte_stream:
    pos = byte_stream.find(b'MythX')
    print(f"FOUND MythX at position {pos}!")
    print(f"Context: {byte_stream[pos:pos+50]}")

# Try: delta_unit as byte directly
print("\nTreating delta_unit as raw byte (mod 256):")
byte_stream2 = bytes([u % 256 for u in delta_units])
print(f"First 100 bytes: {byte_stream2[:100].hex()}")
ascii_s = re.findall(rb'[\x20-\x7e]{4,}', byte_stream2)
print(f"ASCII strings: {ascii_s[:20]}")

# The deviations being powers of 2 is very suspicious
# What if each non-standard packet sets a single bit,
# and we need to accumulate bits across multiple packets to form bytes?
print("\n\n=== BIT ACCUMULATION THEORY ===")
# Group the deltas into chunks where we accumulate bits
# Every 8 non-zero deviations form one byte?

nonzero_dev_values = [d for _, d in nonzero_devs]
print(f"First 30 non-zero deviations: {nonzero_dev_values[:30]}")

# Each deviation is a power of 2, representing a bit position
# Within a byte (0-7), the bit is set
# But which byte does it belong to?

# Theory: split by the packet position - every N packets is one byte
# N = 3001 / (total_message_length)
# If message is about 50 chars (flag), N ≈ 60

# Alternative: look at the GAPS between non-standard packets
# Gap between packets = which byte in the output
gaps = [nonzero_devs[i+1][0] - nonzero_devs[i][0] for i in range(len(nonzero_devs)-1)]
print(f"\nGaps between non-standard packets (first 30): {gaps[:30]}")

# Or: the 8 bits of a byte are spread across 8 non-zero deviations
# deviation value = 2^bit_position, and we group every 8 
print("\nGrouping every 8 non-zero deviations into one byte:")
result = bytearray()
for i in range(0, len(nonzero_dev_values) - 7, 8):
    byte_val = 0
    for j in range(8):
        dev = nonzero_dev_values[i + j]
        if dev > 0:
            bit = int(round(math.log2(dev)))
            byte_val |= (1 << bit)
    result.append(byte_val)
    
print(f"Result (first 50 chars): {result[:50].hex()}")
print(f"ASCII: {bytes(result[:50])}")
ascii_s = re.findall(rb'[\x20-\x7e]{4,}', bytes(result))
print(f"ASCII strings: {ascii_s[:20]}")

# What if the deviation value IS the bit (1, 2, 4, 8, 16, 32, 64, 128)
# And we OR them together until we see a "reset" (back to base)?
print("\n\n=== OR accumulation between bases ===")
result2 = bytearray()
current_byte = 0
for d in all_dev_values:
    if d == 0:
        # Base heartbeat = separator
        if current_byte != 0:
            result2.append(current_byte)
            current_byte = 0
    else:
        current_byte |= (d & 0xFF)

if current_byte != 0:
    result2.append(current_byte)
    
print(f"Result length: {len(result2)}")
print(f"Result (first 50): {result2[:50].hex()}")
print(f"ASCII: {bytes(result2[:50])}")
ascii_s = re.findall(rb'[\x20-\x7e]{4,}', bytes(result2))
print(f"ASCII strings: {ascii_s[:30]}")

# What if we OR consecutive non-zero deviations?
# Group by runs of non-zero
print("\n\n=== OR accumulation by runs ===")
result3 = bytearray()
current_byte = 0
in_run = False
for d in all_dev_values:
    if d != 0:
        current_byte |= (d & 0xFF)
        in_run = True
    else:
        if in_run:
            result3.append(current_byte)
            current_byte = 0
            in_run = False

if in_run:
    result3.append(current_byte)

print(f"Result3 length: {len(result3)}")
print(f"Result3 (first 80): {result3[:80].hex()}")
print(f"ASCII: {bytes(result3[:80])}")
ascii_s = re.findall(rb'[\x20-\x7e]{4,}', bytes(result3))
print(f"ASCII strings: {ascii_s[:30]}")

# Check for MythX in all results
for name, data in [("result", bytes(result)), ("result2", bytes(result2)), ("result3", bytes(result3))]:
    if b'MythX' in data:
        pos = data.find(b'MythX')
        print(f"\nFOUND MythX in {name} at pos {pos}: {data[pos:pos+50]}")

# Maybe we need to combine with the payload.bin key
payload_key = bytes.fromhex("f184376b295ff909723748c7865e7e623ba4bb0bbde13f3c131faafdaff3aef6651197dc76d110067dc3d022a90af7dbf36e198543bfe7cc75c9ce329036ddba")

for name, data in [("result", bytes(result)), ("result2", bytes(result2)), ("result3", bytes(result3))]:
    # XOR with payload key (repeating)
    xored = bytes(data[i] ^ payload_key[i % len(payload_key)] for i in range(len(data)))
    if b'MythX' in xored:
        pos = xored.find(b'MythX')
        print(f"\nFOUND MythX in XOR({name}, payload_key) at pos {pos}: {xored[pos:pos+50]}")
    ascii_s = re.findall(rb'[\x20-\x7e]{6,}', xored)
    if ascii_s:
        print(f"XOR({name}, payload_key) ASCII: {ascii_s[:20]}")

# ========================================
# Let me revisit: What if the non-zero deviations represent the bit number,
# and the index of the deviation tells us the POSITION in the output byte array?
# 
# Actually wait - let me reconsider the structure:
# 3002 packets, 3001 deltas
# 2,097,152 bytes = 16,777,216 bits
# 3001 "heartbeats" to encode 16M+ bits? No...
#
# "Heartbeat bridging the network and RAM" 
# Maybe: the timing tells us WHICH bytes from memory to extract?
# The deviation is a bit mask or index?

# Theory: Non-zero deviation value = memory page offset
# Pointer into the memory dump
print("\n\n=== DEVIATION AS MEMORY INDEX ===")
for scale in [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048]:
    extracted = bytearray()
    for _, dev in nonzero_devs:
        offset = dev * scale
        if 0 <= offset < len(mem_data):
            extracted.append(mem_data[offset])
    if len(extracted) > 0:
        ascii_s = re.findall(rb'[\x20-\x7e]{6,}', bytes(extracted))
        if ascii_s:
            print(f"  dev*{scale}: {ascii_s[:5]}")

# Maybe: packet_index * deviation = memory offset
print("\n=== PACKET_INDEX * DEVIATION = MEMORY OFFSET ===")
extracted = bytearray()
for idx, dev in nonzero_devs:
    offset = idx * dev
    if 0 <= offset < len(mem_data):
        extracted.append(mem_data[offset])
ascii_s = re.findall(rb'[\x20-\x7e]{4,}', bytes(extracted))
print(f"  idx*dev: {ascii_s[:10]}")

# ========================================
# Let me think about this from the flag format perspective
# Flag is MythX{...} - let's see if any encoding of M(77), y(121), t(116), h(104), X(88)
# maps to the timing pattern

# For the first few non-zero deviations:
# Position 0: dev=16  (2^4)
# Position 1: dev=8   (2^3)
# Position 15: dev=48 (2^5 + 2^4 = 32+16)  -- NOT a power of 2!
# Position 16: dev=128 (2^7)
# Position 22: dev=4  (2^2)

# Wait, 48 is NOT a power of 2 (48 = 32+16)
# So my powers-of-2 theory was wrong. Let me recheck.

print("\n=== RECHECK: Are deviations actually powers of 2? ===")
for d in unique_devs:
    if d > 0:
        is_pow2 = d != 0 and (d & (d-1)) == 0
        print(f"  {d:4d} = 0b{d:08b} {'✓ power of 2' if is_pow2 else '✗ NOT power of 2'}")
    elif d < 0:
        print(f"  {d:4d} = negative")
