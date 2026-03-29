from scapy.all import rdpcap, DNS, DNSQR
import hashlib
import re
from Crypto.Cipher import AES

packets = rdpcap("capture_og0oXNg.pcap")
dns_packets = [pkt for pkt in packets if pkt.haslayer(DNS) and pkt.haslayer(DNSQR)]

timestamps = [float(pkt.time) for pkt in dns_packets]
deltas = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

with open("memory_IcOZWTs.dmp", "rb") as f:
    mem_data = f.read()

password = b"Rabb1tH0le123!"
payload = bytes.fromhex("f184376b295ff909723748c7865e7e623ba4bb0bbde13f3c131faafdaff3aef6651197dc76d110067dc3d022a90af7dbf36e198543bfe7cc75c9ce329036ddba")

BASE = 259  # 8.09375 * 32
delta_units = [round(d * 32) for d in deltas]
dev_units = [BASE - u for u in delta_units]

# The timing deviations encode information
# 1089 non-zero deviations, 1912 zeros
# Deviations are the "heartbeat" that "bridges" the network and RAM

# THEORY: The timing deviations tell us which BYTES from memory to extract
# Each non-zero deviation = a byte offset or selector
# The assembled bytes from memory form the encrypted real flag

# Let me look at the deviation values more carefully
non_zero = [(i, d) for i, d in enumerate(dev_units) if d != 0]
print(f"Non-zero deviations: {len(non_zero)}")

# The deviations range from -16 to 255
# Most are: 1, 2, 4, 8, 16, 32, 48, 64, 128
# And these are exactly bit positions! (except 48 = 32+16)

# IMPORTANT: The deviations are CUMULATIVE to form byte values
# When we see consecutive non-zero deviations, they're bits of one byte
# When we see a zero (normal heartbeat), it's a separator

# Let's try: build bytes by ORing consecutive non-zero deviations
print("\n=== Building bytes by ORing consecutive non-zeros ===")
result_bytes = bytearray()
current = 0
in_sequence = False

for d in dev_units:
    if d != 0 and d > 0:
        current |= d
        in_sequence = True
    else:
        if in_sequence:
            result_bytes.append(current & 0xFF)
            current = 0
            in_sequence = False

if in_sequence:
    result_bytes.append(current & 0xFF)

print(f"Extracted {len(result_bytes)} bytes")
print(f"Hex: {result_bytes.hex()}")
print(f"ASCII: {bytes(result_bytes)}")
ascii_s = re.findall(rb'[\x20-\x7e]{4,}', bytes(result_bytes))
print(f"ASCII strings: {ascii_s[:20]}")

# Check for MythX
if b'MythX' in bytes(result_bytes):
    pos = bytes(result_bytes).find(b'MythX')
    print(f"FOUND MythX at {pos}: {bytes(result_bytes)[pos:pos+60]}")

# Try AES decryption on this data
key_sha256 = hashlib.sha256(password).digest()
if len(result_bytes) >= 16 and len(result_bytes) % 16 == 0:
    # ECB
    cipher = AES.new(key_sha256, AES.MODE_ECB)
    dec = cipher.decrypt(bytes(result_bytes))
    print(f"AES-ECB decrypt: {dec}")
    
    # CBC with IV=0
    cipher = AES.new(key_sha256, AES.MODE_CBC, iv=b'\x00'*16)
    dec = cipher.decrypt(bytes(result_bytes))
    print(f"AES-CBC(IV=0) decrypt: {dec}")
    
    # CBC with IV from first 16 bytes
    if len(result_bytes) > 16:
        cipher = AES.new(key_sha256, AES.MODE_CBC, iv=bytes(result_bytes[:16]))
        dec = cipher.decrypt(bytes(result_bytes[16:]))
        print(f"AES-CBC(IV=data[:16]) decrypt: {dec}")

# =============================================
# ALTERNATIVE: Instead of OR, try ADDITION
# =============================================
print("\n=== Building bytes by ADDING consecutive non-zeros ===")
result_add = bytearray()
current = 0
in_sequence = False

for d in dev_units:
    if d != 0 and d > 0:
        current += d
        in_sequence = True
    else:
        if in_sequence:
            result_add.append(current & 0xFF)
            current = 0
            in_sequence = False

if in_sequence:
    result_add.append(current & 0xFF)

print(f"Extracted {len(result_add)} bytes")
print(f"Hex: {result_add.hex()}")
print(f"ASCII: {bytes(result_add)}")
ascii_s = re.findall(rb'[\x20-\x7e]{4,}', bytes(result_add))
print(f"ASCII strings: {ascii_s[:20]}")

# =============================================
# What if each group represents a memory OFFSET?
# =============================================
print("\n=== ORed groups as memory offsets ===")
# Use the ORed values (or added values) as offsets into memory
for name, data in [("OR groups", result_bytes), ("ADD groups", result_add)]:
    for scale in [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192]:
        extracted = bytearray()
        for b in data:
            offset = b * scale
            if 0 <= offset < len(mem_data):
                extracted.append(mem_data[offset])
        ascii_s = re.findall(rb'[\x20-\x7e]{6,}', bytes(extracted))
        if ascii_s:
            print(f"  {name} * {scale}: {ascii_s[:5]}")

# =============================================
# What if the combined value (OR of group) is the actual byte and we should 
# XOR it with memory bytes at specific offsets derived from group START POSITION?
# =============================================
print("\n=== ORed value XOR memory[group_start_position] ===")
group_results = []  # (start_pos, ored_value)
current = 0
start_pos = None
in_sequence = False

for i, d in enumerate(dev_units):
    if d != 0 and d > 0:
        if not in_sequence:
            start_pos = i
        current |= d
        in_sequence = True
    else:
        if in_sequence:
            group_results.append((start_pos, current & 0xFF))
            current = 0
            in_sequence = False

if in_sequence:
    group_results.append((start_pos, current & 0xFF))

print(f"Total groups: {len(group_results)}")
print(f"First 20 groups (pos, value): {group_results[:20]}")

for mem_scale in [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 700, 1024]:
    extracted = bytearray()
    for pos, val in group_results:
        offset = pos * mem_scale
        if offset < len(mem_data):
            extracted.append(mem_data[offset] ^ val)
    ascii_s = re.findall(rb'[\x20-\x7e]{6,}', bytes(extracted))
    if ascii_s:
        print(f"  mem_scale={mem_scale}: {ascii_s[:5]}")

# =============================================
# Also: try ADD groups as memory offsets
# =============================================
print("\n=== ADD groups as direct memory offsets ===")
add_groups = []
current = 0
start_pos = None
in_sequence = False

for i, d in enumerate(dev_units):
    if d != 0 and d > 0:
        if not in_sequence:
            start_pos = i
        current += d
        in_sequence = True
    else:
        if in_sequence:
            add_groups.append((start_pos, current))
            current = 0
            in_sequence = False

if in_sequence:
    add_groups.append((start_pos, current))

print(f"ADD group values (first 20): {[v for _, v in add_groups[:20]]}")
print(f"Min: {min(v for _, v in add_groups)}, Max: {max(v for _, v in add_groups)}")

# Use add group values directly as memory offsets
extracted = bytearray()
for _, offset in add_groups:
    if 0 <= offset < len(mem_data):
        extracted.append(mem_data[offset])
print(f"Extracted from ADD offsets: {bytes(extracted[:100])}")
ascii_s = re.findall(rb'[\x20-\x7e]{4,}', bytes(extracted))
print(f"ASCII: {ascii_s[:20]}")

# Scale the ADD offsets
for scale in [2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096]:
    extracted = bytearray()
    for _, val in add_groups:
        offset = val * scale
        if 0 <= offset < len(mem_data):
            extracted.append(mem_data[offset])
    ascii_s = re.findall(rb'[\x20-\x7e]{6,}', bytes(extracted))
    if ascii_s:
        print(f"  ADD*{scale}: {ascii_s[:5]}")

# =============================================
# What if the ORed/added bytes need to be decrypted?
# Use as ciphertext with the AES key
# =============================================
print("\n\n=== Decrypt OR-assembled bytes ===")
# Pad to multiple of 16
data = bytes(result_bytes)
if len(data) % 16 != 0:
    padded = data + b'\x00' * (16 - len(data) % 16)
else:
    padded = data

cipher = AES.new(key_sha256, AES.MODE_ECB)
dec = cipher.decrypt(padded)
ascii_s = re.findall(rb'[\x20-\x7e]{4,}', dec)
print(f"AES-ECB: {ascii_s[:20]}")

cipher = AES.new(key_sha256, AES.MODE_CBC, iv=b'\x00'*16)
dec = cipher.decrypt(padded)
ascii_s = re.findall(rb'[\x20-\x7e]{4,}', dec)
print(f"AES-CBC(IV=0): {ascii_s[:20]}")

# Try with first 16 bytes as IV
if len(data) > 16:
    rest = data[16:]
    if len(rest) % 16 != 0:
        rest = rest + b'\x00' * (16 - len(rest) % 16)
    cipher = AES.new(key_sha256, AES.MODE_CBC, iv=data[:16])
    dec = cipher.decrypt(rest)
    ascii_s = re.findall(rb'[\x20-\x7e]{4,}', dec)
    print(f"AES-CBC(IV=data[:16]): {ascii_s[:20]}")

# =============================================
# Let me try the ADD-assembled bytes as ciphertext
# =============================================
print("\n=== Decrypt ADD-assembled bytes ===")
data = bytes(min(v, 255) for _, v in add_groups)
if len(data) % 16 != 0:
    padded = data + b'\x00' * (16 - len(data) % 16)
else:
    padded = data

cipher = AES.new(key_sha256, AES.MODE_ECB)
dec = cipher.decrypt(padded)
ascii_s = re.findall(rb'[\x20-\x7e]{4,}', dec)
print(f"AES-ECB: {ascii_s[:20]}")

cipher = AES.new(key_sha256, AES.MODE_CBC, iv=b'\x00'*16)
dec = cipher.decrypt(padded)
ascii_s = re.findall(rb'[\x20-\x7e]{4,}', dec)
print(f"AES-CBC(IV=0): {ascii_s[:20]}")

if len(data) > 16:
    rest = data[16:]
    if len(rest) % 16 != 0:
        rest = rest + b'\x00' * (16 - len(rest) % 16)
    cipher = AES.new(key_sha256, AES.MODE_CBC, iv=data[:16])
    dec = cipher.decrypt(rest)
    ascii_s = re.findall(rb'[\x20-\x7e]{4,}', dec)
    print(f"AES-CBC(IV=data[:16]): {ascii_s[:20]}")

# =============================================
# CRUCIAL RETHINK: The challenge says "heartbeat bridging network and RAM"
# + "bypassing decoys"
# 
# The timing IS encoding something directly.
# Let me check if the OR-assembled bytes look like anything specific
# =============================================
print("\n\n=== DETAILED OR-ASSEMBLY ===")
groups_detail = []
current_bits = []
in_seq = False
for i, d in enumerate(dev_units):
    if d > 0:
        current_bits.append(d)
        in_seq = True
    else:
        if in_seq:
            ored = 0
            for b in current_bits:
                ored |= b
            groups_detail.append((len(current_bits), ored, current_bits[:]))
            current_bits = []
            in_seq = False

if in_seq:
    ored = 0
    for b in current_bits:
        ored |= b
    groups_detail.append((len(current_bits), ored, current_bits[:]))

print(f"Number of groups: {len(groups_detail)}")
print(f"Group sizes distribution: {dict((s, sum(1 for g in groups_detail if g[0] == s)) for s in set(g[0] for g in groups_detail))}")
print(f"\nFirst 30 groups (size, ored_value, bits):")
for g in groups_detail[:30]:
    print(f"  size={g[0]}, value={g[1]:3d} (0x{g[1]:02x}, '{chr(g[1]) if 32 <= g[1] < 127 else '.'}'), bits={g[2]}")
