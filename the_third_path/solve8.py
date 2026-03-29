from scapy.all import rdpcap, DNS, DNSQR
import hashlib
import re
from Crypto.Cipher import AES

packets = rdpcap("capture_og0oXNg.pcap")
dns_packets = [pkt for pkt in packets if pkt.haslayer(DNS) and pkt.haslayer(DNSQR)]

timestamps = [float(pkt.time) for pkt in dns_packets]
deltas = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

with open("memory_IcOZWTs.dmp", "rb") as f:
    mem_data = bytearray(f.read())

password = b"Rabb1tH0le123!"
key_sha256 = hashlib.sha256(password).digest()
payload = bytes.fromhex("f184376b295ff909723748c7865e7e623ba4bb0bbde13f3c131faafdaff3aef6651197dc76d110067dc3d022a90af7dbf36e198543bfe7cc75c9ce329036ddba")

BASE = 259  # 8.09375 * 32
delta_units = [round(d * 32) for d in deltas]
dev_units = [BASE - u for u in delta_units]

# =============================================
# THEORY: Each non-standard timing delta tells us which BIT to 
# extract from the memory dump at a position determined by
# the packet's sequential index among non-standard packets
# 
# Or: the packet number is the BYTE INDEX, and the deviation
# tells us which BIT of that byte in memory to look at
# =============================================

print("=== BIT EXTRACTION FROM MEMORY ===")
# For each non-zero deviation, read memory[packet_index] and check 
# if the specific bit (indicated by deviation) is set

# First, what are the deviation values? They should map to bit positions 0-7
# dev=1 -> bit 0, dev=2 -> bit 1, dev=4 -> bit 2, ...
# dev=128 -> bit 7

# But some devs are 48, 24, etc (not pure powers of 2)
# Those could represent multiple bit extractions at once

# Let me try: for each non-std packet, the deviation value IS the extracted bits
# Then the assembled stream of these values IS the hidden data
# The packet index tells us WHERE in the message stream this goes

# Actually, let me reconsider completely.
# 3002 packets, each with ~8 second intervals
# 1912 are "base" (8.09375s)
# 1089 are "deviated"
# 
# What if EVERY packet contributes a bit?
# delta > threshold = 1, delta < threshold = 0
# 3001 bits / 8 = 375 bytes

# But the threshold is tricky with the continuous distribution

# =============================================
# FRESH APPROACH: What if the cumulative timing drift from
# expected position IS the extracted data?
# Expected: packet N arrives at time N * 8.09375
# Actual: arrives at actual_time[N]
# Drift = actual - expected
# The drift accumulates and encodes an offset into memory
# =============================================
print("=== CUMULATIVE DRIFT ANALYSIS ===")
start_ts = timestamps[0]
# Expected time for each packet
expected = [start_ts + i * 8.09375 for i in range(len(timestamps))]
drifts = [timestamps[i] - expected[i] for i in range(len(timestamps))]

# Look at the cumulative drift in 1/32 units
drift_units_32 = [round(d * 32) for d in drifts]
print(f"Drift units (first 30): {drift_units_32[:30]}")
print(f"Drift units range: {min(drift_units_32)} to {max(drift_units_32)}")

# The drift keeps decreasing. By the end:
print(f"Drift at end: {drift_units_32[-1]}")
print(f"Drift units (last 30): {drift_units_32[-30:]}")

# =============================================
# COMPLETELY NEW APPROACH: Maybe the 389 OR-grouped bytes need 
# to be used as offsets into the memory dump. 
# Each byte (0-255) gives us a position, and we read 
# from memory at that position to get the real flag
# =============================================

# Build OR groups
groups = []
current = 0
in_seq = False
for d in dev_units:
    if d > 0:
        current |= d
        in_seq = True
    else:
        if in_seq:
            groups.append(current & 0xFF)
            current = 0
            in_seq = False
if in_seq:
    groups.append(current & 0xFF)

print(f"\n\n=== 389 OR-grouped bytes ===")
print(f"Values: {groups[:50]}")

# =============================================
# Wait - Let me reconsider the memory dump.
# It has near-maximum entropy (7.999) which means it's encrypted.
# The only plaintext regions are:
# 1. The "svchost.exe VirtualAlloc CryptEncrypt YOUR FILES ARE ENCRYPTED!!" section
# 2. The "C:\Users\admin\Downloads\payload.bin Password is Rabb1tH0le123!" section
# 3. Random short strings from chance
#
# The decoy flag is in memory, the second decoy is in encrypted payload
# The REAL flag must be hidden in the interaction BETWEEN network timing and memory
#
# KEY INSIGHT from challenge: "bypassing decoys to find the truth"
# 
# What if the non-standard timing pattern is used to XOR/modify 
# specific bytes in the encrypted memory to reveal the flag?
# =============================================

print("\n\n=== MODIFY MEMORY WITH TIMING BITS ===")
# For each non-standard delta at position i, XOR memory byte at some index
# with the deviation value

# The 1089 non-standard packets' positions go from 0 to ~3000
# These map to byte positions in memory somehow

# Strategy: Use packet_position as byte index, XOR with deviation
mem_copy = bytearray(mem_data)
for i, d in enumerate(dev_units):
    if d > 0 and d <= 255:
        mem_copy[i] ^= d

# Check if this reveals the flag
flag_pos = mem_copy.find(b'MythX')
if flag_pos >= 0:
    print(f"FOUND MythX at pos {flag_pos}: {mem_copy[flag_pos:flag_pos+60]}")
else:
    # Check first 4000 bytes for ASCII
    ascii_s = re.findall(rb'[\x20-\x7e]{6,}', mem_copy[:4000])
    if ascii_s:
        print(f"ASCII in modified mem[:4000]: {ascii_s[:20]}")

# Also try XOR with the full deviation (not just > 0)
mem_copy2 = bytearray(mem_data)
for i, d in enumerate(dev_units):
    if d != 0:
        mem_copy2[i] ^= (abs(d) & 0xFF)

ascii_s = re.findall(rb'MythX\{[^\}]+\}', bytes(mem_copy2))
if ascii_s:
    print(f"FOUND flag in mem_copy2: {ascii_s}")
else:
    ascii_s = re.findall(rb'[\x20-\x7e]{8,}', mem_copy2[:5000])
    if ascii_s:
        print(f"ASCII in modified mem2[:5000]: {ascii_s[:20]}")

# =============================================
# What if we need to use the timing to find specific offsets 
# in the LARGE memory dump (2MB) to extract a message?
# 
# 3001 deltas, each gives a number 0-275 in units of 1/32
# Use cumulative sum as offset?
# =============================================
print("\n\n=== CUMULATIVE SUM OF ALL DELTAS AS MEMORY POINTER ===")
cum = 0
positions = []
for u in delta_units:
    cum += u
    positions.append(cum % len(mem_data))

# Extract bytes at these positions
extracted = bytes(mem_data[p] for p in positions[:500])
ascii_s = re.findall(rb'[\x20-\x7e]{6,}', extracted)
if ascii_s:
    print(f"Cumulative delta positions: {ascii_s[:10]}")

# =============================================
# What about using the AES key (SHA256 of password) + the timing
# data to find/decrypt a hidden ciphertext IN the memory dump?
# =============================================

# The memory is 2MB of high-entropy data. What if the WHOLE thing is AES encrypted?
# Decrypt the whole memory dump with the AES key
print("\n\n=== DECRYPT ENTIRE MEMORY DUMP WITH AES ===")
cipher = AES.new(key_sha256, AES.MODE_ECB)
# Decrypt just sections around interesting offsets
for start_offset in [0, 309484, 1688800, 1688900]:
    # Align to 16 bytes
    aligned = (start_offset // 16) * 16
    chunk = bytes(mem_data[aligned:aligned+256])
    if len(chunk) == 256:
        dec = cipher.decrypt(chunk)
        ascii_s = re.findall(rb'[\x20-\x7e]{6,}', dec)
        if ascii_s:
            print(f"  ECB at offset {aligned}: {ascii_s[:5]}")

# Try CBC with different IVs
for iv_source in [b'\x00'*16, payload[:16], key_sha256[:16]]:
    cipher = AES.new(key_sha256, AES.MODE_CBC, iv=iv_source)
    for start_offset in [0, 16, 32, 309488, 1688896, 1688912]:
        aligned = (start_offset // 16) * 16
        chunk = bytes(mem_data[aligned:aligned+256])
        if len(chunk) == 256:
            dec = cipher.decrypt(chunk)
            ascii_s = re.findall(rb'[\x20-\x7e]{6,}', dec)
            if ascii_s:
                print(f"  CBC(iv={iv_source[:4].hex()}) at offset {aligned}: {ascii_s[:5]}")

# =============================================
# What if the timing deviation at position i tells us the BIT POSITION  
# to extract from memory byte at position i, and we concatenate 
# those bits to form the flag?
# =============================================
print("\n\n=== EXTRACT SPECIFIC BITS FROM MEMORY ===")
import math
bits_stream = []
for i, d in enumerate(dev_units):
    if d > 0 and (d & (d-1)) == 0:  # power of 2
        bit_pos = int(round(math.log2(d)))
        if i < len(mem_data):
            bit_val = (mem_data[i] >> bit_pos) & 1
            bits_stream.append(bit_val)

print(f"Extracted {len(bits_stream)} bits from power-of-2 deviations")
# Convert bits to bytes
byte_result = bytearray()
for j in range(0, len(bits_stream) - 7, 8):
    byte_val = 0
    for k in range(8):
        byte_val |= (bits_stream[j+k] << (7-k))
    byte_result.append(byte_val)

print(f"Bytes: {bytes(byte_result[:50]).hex()}")
print(f"ASCII: {bytes(byte_result[:50])}")
ascii_s = re.findall(rb'[\x20-\x7e]{4,}', bytes(byte_result))
print(f"ASCII strings: {ascii_s[:20]}")

# Try with LSB first
byte_result2 = bytearray()
for j in range(0, len(bits_stream) - 7, 8):
    byte_val = 0
    for k in range(8):
        byte_val |= (bits_stream[j+k] << k)
    byte_result2.append(byte_val)

print(f"\nLSB first: {bytes(byte_result2[:50])}")
ascii_s = re.findall(rb'[\x20-\x7e]{4,}', bytes(byte_result2))
print(f"ASCII strings: {ascii_s[:20]}")

# =============================================
# Let me also try with ALL non-zero deviations (not just power of 2)
# treating the deviation as a mask
# =============================================
print("\n\n=== MASKED BIT EXTRACTION ===")
bits_stream2 = []
for i, d in enumerate(dev_units):
    if d != 0 and 0 < d <= 255 and i < len(mem_data):
        masked = mem_data[i] & d
        # Count number of set bits in mask to know how many bits to extract
        for bit in range(8):
            if d & (1 << bit):
                bits_stream2.append((mem_data[i] >> bit) & 1)

print(f"Extracted {len(bits_stream2)} bits")
byte_result3 = bytearray()
for j in range(0, len(bits_stream2) - 7, 8):
    byte_val = 0
    for k in range(8):
        byte_val |= (bits_stream2[j+k] << (7-k))
    byte_result3.append(byte_val)

print(f"Bytes: {bytes(byte_result3[:80])}")
ascii_s = re.findall(rb'[\x20-\x7e]{4,}', bytes(byte_result3))
print(f"ASCII strings: {ascii_s[:20]}")

if b'MythX' in bytes(byte_result3):
    pos = bytes(byte_result3).find(b'MythX')
    print(f"FOUND FLAG: {bytes(byte_result3)[pos:pos+60]}")

# =============================================
# FINAL IDEA: "Heartbeat" = timing pattern
# "Bridging network and RAM" = combine DNS timing with memory offsets
# 
# What if: the timing deviation gives an offset INTO the memory dump
# (scaled appropriately) and we extract bytes from those offsets?
# 
# There are 1089 non-std packets.
# The first ~130 OR-groups are clean single-byte values (size=1)
# These seem like they could be memory page numbers or something
#
# Let me think about scale: memory is 2^21 bytes = 2097152
# 2097152 / 256 = 8192 = 2^13
# So each byte value (0-255) selects one of 256 pages of 8192 bytes
# But which byte within the page?
#
# Maybe: (packet_position * 8192 / 3001) gives the page
# and the deviation value gives the offset within the page?
# That seems overcomplicated.
#
# Simpler: maybe we use packet_position to create a base offset
# and the deviation value to select which bits within that offset
# =============================================

# Let me just search for MythX pattern in the entire memory XORed with various things
print("\n\n=== BRUTE FORCE XOR KEY SEARCH IN MEMORY ===")
# Try single-byte XOR
for key_byte in range(256):
    test = bytes(b ^ key_byte for b in mem_data[1688800:1689000])
    if b'MythX{' in test and b'd3c0y' not in test:
        pos = test.find(b'MythX{')
        print(f"  XOR {key_byte:#04x}: {test[pos:pos+50]}")

# Try XOR with key_sha256
test = bytes(mem_data[i] ^ key_sha256[i % 32] for i in range(len(mem_data)))
positions = [m.start() for m in re.finditer(rb'MythX\{', test)]
if positions:
    for p in positions:
        flag = test[p:p+80]
        if b'd3c0y' not in flag:
            print(f"  XOR sha256 at {p}: {flag}")

# =============================================
# Actually, I wonder if the whole memory is XOR-encrypted with a key
# derived from timing. Let me check if XOR with all-0x93 reveals something
# (since memory starts with 0x93 and high entropy suggests encryption)
# =============================================
print("\n\n=== CHECK IF MEMORY IS XOR-ENCRYPTED ===")
# If memory byte 0 = 0x93, and it should be 0x00 (for a typical header),
# then key = 0x93
test = bytes(b ^ 0x93 for b in mem_data[:200])
print(f"XOR 0x93: {test[:50].hex()}")
print(f"ASCII: {''.join(chr(b) if 32 <= b < 127 else '.' for b in test[:50])}")
