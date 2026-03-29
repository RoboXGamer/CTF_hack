from scapy.all import rdpcap, DNS, DNSQR
import hashlib
import re
import math
import itertools
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

packets = rdpcap("capture_og0oXNg.pcap")
dns_packets = [pkt for pkt in packets if pkt.haslayer(DNS) and pkt.haslayer(DNSQR)]

timestamps = [float(pkt.time) for pkt in dns_packets]
deltas = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

with open("memory_IcOZWTs.dmp", "rb") as f:
    mem_data = f.read()

password = b"Rabb1tH0le123!"
key_sha256 = hashlib.sha256(password).digest()
key_md5 = hashlib.md5(password).digest()
payload = bytes.fromhex("f184376b295ff909723748c7865e7e623ba4bb0bbde13f3c131faafdaff3aef6651197dc76d110067dc3d022a90af7dbf36e198543bfe7cc75c9ce329036ddba")

BASE = 259  # 8.09375 * 32
delta_units = [round(d * 32) for d in deltas]
dev_units = [BASE - u for u in delta_units]

# Build the 389 OR-assembled bytes 
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

data_389 = bytes(groups)
print(f"389 OR-grouped bytes: {len(data_389)}")

# The second decoy was found using AES-CBC with SHA256(password) key
# and first 16 bytes of payload as IV
# 
# What if we need a DIFFERENT key? 
# Or what if the 389 bytes ARE the ciphertext for the real flag?

# Let's try decrypting the 389 bytes various ways
# First pad to 400 (25 * 16) or trim to 384 (24 * 16)
data_384 = data_389[:384]  # trim to multiple of 16

print("\n=== Decrypt 384-byte timing data ===")
# Various keys
keys = {
    'sha256(pw)': key_sha256,
    'md5(pw)': key_md5,
    'payload[:32]': payload[:32],
    'payload[32:]': payload[32:],
    'sha256(payload)': hashlib.sha256(payload).digest(),
}

ivs = {
    'zeros': b'\x00' * 16,
    'payload[:16]': payload[:16],
    'payload[16:32]': payload[16:32],
    'payload[48:]': payload[48:],
    'sha256(pw)[:16]': key_sha256[:16],
    'md5(pw)': key_md5,
}

for key_name, key in keys.items():
    # ECB
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        dec = cipher.decrypt(data_384)
        if b'MythX' in dec or b'mythx' in dec.lower():
            print(f"  ECB {key_name}: FOUND FLAG: {dec}")
        ascii_s = re.findall(rb'[\x20-\x7e]{8,}', dec)
        if ascii_s:
            print(f"  ECB {key_name}: {ascii_s[:5]}")
    except: pass
    
    # CBC with various IVs
    for iv_name, iv in ivs.items():
        try:
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            dec = cipher.decrypt(data_384)
            if b'MythX' in dec or b'mythx' in dec.lower():
                print(f"  CBC {key_name}/{iv_name}: FOUND FLAG: {dec}")
            ascii_s = re.findall(rb'[\x20-\x7e]{8,}', dec)
            if ascii_s:
                print(f"  CBC {key_name}/{iv_name}: {ascii_s[:5]}")
        except: pass

# =============================================
# Let me also re-examine the relationship differently.
# 
# What if the timing doesn't encode DATA but rather
# encodes a XOR KEY to apply to the AES-decrypted payload?
# 
# We decrypted payload -> "nice_try_but_keep_looking" (decoy)
# What if we need to XOR that with something from timing?
# =============================================
decoy2 = b'MythX{nice_try_but_keep_looking}'
print(f"\nDecoy 2: {decoy2}")
print(f"Decoy 2 hex: {decoy2.hex()}")

# What if we XOR decoy2 with some timing-derived key?
# The 389 grouped bytes... first 32 bytes:
timing_key = data_389[:32]
xored = bytes(a ^ b for a, b in zip(decoy2, timing_key))
print(f"Decoy2 XOR timing[:32]: {xored}")

# =============================================
# Let me think about this more carefully.
# The challenge says "heartbeat bridging network and RAM"
# The decoy2 says "keep looking"
# 
# Maybe the AES decryption of the payload gives us another KEY
# that we need to apply to something in the memory dump?
# Or maybe we need to look at what happens when we use
# the decrypted value "nice_try_but_keep_looking" as a key?
# =============================================
print("\n\n=== Using decoy text as key ===")
decoy_key_sha256 = hashlib.sha256(decoy2).digest()
print(f"SHA256 of decoy2: {decoy_key_sha256.hex()}")

# Decrypt payload with this new key
for iv_name, iv in ivs.items():
    try:
        cipher = AES.new(decoy_key_sha256, AES.MODE_CBC, iv=iv)
        dec = cipher.decrypt(payload[16:])
        if b'MythX' in dec:
            print(f"  Payload CBC {iv_name}: FOUND: {dec}")
        ascii_s = re.findall(rb'[\x20-\x7e]{6,}', dec)
        if ascii_s:
            print(f"  Payload CBC {iv_name}: {ascii_s[:5]}")
    except: pass

# Decrypt memory sections with this key
cipher = AES.new(decoy_key_sha256, AES.MODE_ECB)
for offset in range(0, len(mem_data) - 255, 256):
    dec = cipher.decrypt(mem_data[offset:offset+256])
    if b'MythX' in dec:
        print(f"  Memory ECB at {offset}: FOUND: {dec}")
        break

# =============================================
# BACK TO BASICS: Let me search the entire memory dump 
# for ALL occurrences of "MythX" including obfuscated versions
# =============================================
print("\n\n=== COMPREHENSIVE MYTHX SEARCH ===")
# Standard search
for pattern in [b'MythX{', b'MythX', b'MYTHX', b'mythx']:
    positions = [m.start() for m in re.finditer(re.escape(pattern), mem_data)]
    if positions:
        for p in positions:
            context = mem_data[p:p+60]
            print(f"  '{pattern.decode()}' at {p}: {context}")

# Base64-encoded MythX
import base64
mythx_b64 = base64.b64encode(b'MythX{')
print(f"Base64 of MythX: {mythx_b64}")
pos = mem_data.find(mythx_b64)
if pos >= 0:
    print(f"  Found base64 MythX at {pos}!")

# ROT13
mythx_rot13 = b'ZlguK{'  # ROT13 of MythX{
pos = mem_data.find(mythx_rot13)
if pos >= 0:
    print(f"  Found ROT13 MythX at {pos}!")

# Reversed
pos = mem_data.find(b'}' + b'MythX{'[::-1][1:])
if pos >= 0:
    print(f"  Found reversed MythX at {pos}!")

# =============================================
# What if the timing data IS the secret message itself, 
# just encoded differently? 
# Let me look at the non-standard delta values as ASCII
# =============================================
print("\n\n=== DELTA AS ASCII (various transforms) ===")
non_zero_devs_positive = [d for d in dev_units if d > 0]
non_zero_devs_all = [d for d in dev_units if d != 0]

# Maybe: 256 - deviation = ASCII character
transformed = [256 - d if d > 0 else 256 + d for d in non_zero_devs_all if abs(d) <= 255]
byte_data = bytes(t & 0xFF for t in transformed)
print(f"256-dev: {byte_data[:50]}")
ascii_s = re.findall(rb'[\x20-\x7e]{4,}', byte_data)
print(f"ASCII: {ascii_s[:20]}")

# =============================================
# OK after all this work, let me look at the cumulative drift 
# more carefully. Cumulative drift = -105449 at end
# 105449 / 32 = 3295.28 seconds lost
# 
# But -105449 in hex = -19BD9
# -105449 modulo 2097152 = 2097152 - 105449 = 1991703
# 
# What if the cumulative drift points to a location in memory?
# =============================================
print("\n\n=== CUMULATIVE DRIFT POINTER ===")
start_ts = timestamps[0]
expected = [start_ts + i * 8.09375 for i in range(len(timestamps))]
drifts = [timestamps[i] - expected[i] for i in range(len(timestamps))]
drift_units = [round(d * 32) for d in drifts]

# Track the cumulative drift at each point
# Where the drift equals a notable memory offset
print(f"Final drift: {drift_units[-1]}")
print(f"Final drift mod memsize: {drift_units[-1] % len(mem_data)}")

# What if each unique drift value is a memory pointer?
unique_drifts = sorted(set(drift_units))
print(f"Unique drift values: {len(unique_drifts)}")

#  positive drifts
pos_drifts = sorted(set(d for d in drift_units if d >= 0))
print(f"Non-negative drift values: {pos_drifts}")

# For each drift value, mod into memory and read
mem_from_drifts = bytes(mem_data[d % len(mem_data)] for d in drift_units)
ascii_s = re.findall(rb'[\x20-\x7e]{6,}', mem_from_drifts)
if ascii_s:
    print(f"Memory from drift pointers: {ascii_s[:10]}")

# =============================================
# WHAT IF: We need to take the absolute drift * something as the memory offset?
# Total absolute drift = 105449 in 1/32 units = 3295.28 seconds
# 105449 / 3001 ≈ 35 per delta
# =============================================
abs_drifts = [abs(d) for d in drift_units]
# Extract from memory
extracted = bytes(mem_data[d % len(mem_data)] for d in abs_drifts)
ascii_s = re.findall(rb'[\x20-\x7e]{6,}', extracted)
if ascii_s:
    print(f"Memory from abs_drift pointers: {ascii_s[:10]}")

# =============================================
# Let me try: the delta (in units of 1/32 sec) modulo 256 as byte
# For ALL 3001 deltas (including base ones)
# =============================================
print("\n\n=== ALL DELTA UNITS MOD 256 ===")
all_bytes = bytes([u % 256 for u in delta_units])
print(f"First 50: {all_bytes[:50].hex()}")
# Most will be 259 % 256 = 3
# Let's look at the non-3 ones
non_3 = [(i, all_bytes[i]) for i in range(len(all_bytes)) if all_bytes[i] != 3]
print(f"Non-3 values: {len(non_3)}")
print(f"First 30: {non_3[:30]}")
# These are the deviating packets
# Their values mod 256

# The non-3 bytes
non3_bytes = bytes(v for _, v in non_3)
print(f"Non-3 byte values: {non3_bytes[:50].hex()}")
print(f"ASCII: {non3_bytes[:50]}")
ascii_s = re.findall(rb'[\x20-\x7e]{4,}', non3_bytes)
print(f"ASCII strings: {ascii_s[:20]}")
