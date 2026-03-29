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
key_sha256 = hashlib.sha256(password).digest()
payload = bytes.fromhex("f184376b295ff909723748c7865e7e623ba4bb0bbde13f3c131faafdaff3aef6651197dc76d110067dc3d022a90af7dbf36e198543bfe7cc75c9ce329036ddba")

BASE_DELTA = 8.09375

# =========================================================
# Let me try something completely different.
# The challenge says "subtle heartbeat" - the key signal is the TIMING.
# "bridging the network and RAM" means timing connects to memory.
# 
# What if each timing delta is not just data but an INSTRUCTION?
# e.g., "read memory at offset X, add/xor value Y"
# 
# 3001 deltas:
# - 1912 are "normal" (8.09375s) = NOP / heartbeat  
# - 1089 are "data" = some operation
# 
# The data deltas represent BYTE VALUES (0-255) when converted:
# deviation = BASE - actual_delta, in units of 1/32
# 
# These are between -16 and 255.
# The ones EXACTLY equal to a valid byte (0-255) are 1088.
# They're ASSEMBLED into bytes by OR-ing consecutive ones (389 bytes).
# 
# What if these 389 bytes are used as an AES key, IV, or ciphertext,
# together with data from memory?
# =========================================================

# Actually, let me revisit: I noticed the first few OR-grouped values are
# very small (single bit values: 8, 176, 4, 64, 32, 16, 32, 1, etc.)
# These ARE bit positions, and they should be XOR'd into a buffer
# to reconstruct a message.
# 
# But what if the NUMBER OF ZEROS (heartbeats) between groups 
# tells us the BYTE POSITION?
# i.e., group 1 maps to byte 0, then N zeros = jump N positions,
# then next group maps to byte N, etc.

# Let me build: for each packet position, compute the "accumulated byte"
# by OR-ing deviations
print("=== SPARSE BYTE ARRAY FROM TIMING ===")
delta_units = [round(d * 32) for d in deltas]
dev_units = [259 - u for u in delta_units]

# Build sparse array: each position in 0-3000 maps to a value
# Value at position i = dev_units[i] if non-zero, else skip
# The byte at position i in the output = mem_data[i] ^ dev_units[i]

# First, let's just see what XOR of deviation with memory gives at each position
result = bytearray(3001)
for i in range(3001):
    if dev_units[i] > 0 and dev_units[i] <= 255:
        result[i] = mem_data[i] ^ dev_units[i]
    else:
        result[i] = 0

# Now extract the non-zero bytes
non_zero_bytes = [(i, result[i]) for i in range(3001) if result[i] != 0]
print(f"Non-zero XOR bytes: {len(non_zero_bytes)}")
msg = bytes([b for _, b in non_zero_bytes])
print(f"Message: {msg[:100]}")
ascii_s = re.findall(rb'[\x20-\x7e]{4,}', msg)
print(f"ASCII strings: {ascii_s[:20]}")

if b'MythX' in msg:
    print(f"FOUND FLAG IN MSG!")
    pos = msg.find(b'MythX')
    print(f"  {msg[pos:pos+60]}")

# =========================================================
# ALTERNATIVE: What if we need to AES-decrypt the MEMORY using 
# the 389 timing bytes as some kind of key/IV?
# =========================================================
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

timing_data = bytes(groups)
print(f"\nTiming data ({len(timing_data)} bytes)")

# Use first 32 bytes as AES key
timing_key = timing_data[:32]
print(f"Timing key: {timing_key.hex()}")

# Use first 16 as IV
timing_iv = timing_data[:16]

# Decrypt memory sections
print("\n=== DECRYPT MEMORY WITH TIMING KEY ===")
for mode_name, mode in [("ECB", AES.MODE_ECB), ("CBC", AES.MODE_CBC)]:
    try:
        if mode == AES.MODE_ECB:
            cipher = AES.new(timing_key, mode)
        else:
            cipher = AES.new(timing_key, mode, iv=timing_iv)
        
        # Try various memory offsets
        for offset in range(0, min(len(mem_data), 100000), 16):
            chunk = mem_data[offset:offset+64]
            if len(chunk) == 64:
                dec = cipher.decrypt(chunk)
                if mode == AES.MODE_CBC:
                    cipher = AES.new(timing_key, mode, iv=timing_iv)
                if b'MythX' in dec:
                    print(f"  FOUND at {offset}: {dec}")
    except Exception as e:
        print(f"  Error {mode_name}: {e}")

# =========================================================
# What if the timing-assembled bytes ARE the encrypted flag
# and we decrypt them with the password-derived key?
# =========================================================
print("\n=== DECRYPT TIMING DATA WITH PASSWORD KEY ===")
# Pad to 400 bytes (multiple of 16) 
td_padded = timing_data[:384]  # first 384 bytes

# Use the PAYLOAD as the IV! (first 16 bytes)
cipher = AES.new(key_sha256, AES.MODE_CBC, iv=payload[:16])
dec = cipher.decrypt(td_padded)
print(f"AES-CBC with payload IV: first 100 bytes: {dec[:100]}")
ascii_s = re.findall(rb'[\x20-\x7e]{4,}', dec)
print(f"ASCII: {ascii_s[:20]}")

# Try with IV from decoy flag hash
decoy1 = b'MythX{m3m0ry_r4ns0mw4r3_d3c0y}'
decoy1_hash = hashlib.sha256(decoy1).digest()
cipher = AES.new(decoy1_hash, AES.MODE_CBC, iv=b'\x00'*16)
dec = cipher.decrypt(td_padded)
ascii_s = re.findall(rb'[\x20-\x7e]{4,}', dec)
if ascii_s:
    print(f"AES(SHA256(decoy1)): {ascii_s[:20]}")

# =========================================================
# WHAT IF: The deviation tells how many seconds LESS than base,
# and this number represents the ASCII character directly?
# dev=77 -> 'M'(77), dev=121 -> 'y'(121), etc.
# Let me check: M=77, y=121, t=116, h=104, X=88
# Are any of these in the deviations?
# =========================================================
print("\n=== CHECK DIRECT ASCII IN DEVIATIONS ===")
# Only keep deviations that are valid ASCII (32-126)
ascii_devs = [(i, d) for i, d in enumerate(dev_units) if 32 <= d <= 126]
print(f"Deviations in ASCII range (32-126): {len(ascii_devs)}")
msg_from_devs = ''.join(chr(d) for _, d in ascii_devs)
print(f"Message: {msg_from_devs[:100]}")

# Also try: deviations that are valid ASCII when added to or subtracted from something
# 256 - dev
ascii_devs2 = [(i, 256-d) for i, d in enumerate(dev_units) if 32 <= 256-d <= 126 and d != 0]
print(f"\n256-deviation in ASCII range: {len(ascii_devs2)}")
msg2 = ''.join(chr(v) for _, v in ascii_devs2)
print(f"Message: {msg2[:100]}")

# =========================================================
# Let me also try: the AES-decrypted payload (the decoy message)  
# tells us to "keep looking" - maybe there's more data in the payload
# if decrypted with a different key?
# =========================================================
print("\n\n=== DECRYPT PAYLOAD WITH DIFFERENT KEYS ===")
# What if the 389 timing bytes contain the REAL KEY?
for key_start in range(0, len(timing_data) - 31, 16):
    key = timing_data[key_start:key_start+32]
    try:
        # ECB
        cipher = AES.new(key, AES.MODE_ECB)
        dec = cipher.decrypt(payload)
        if b'MythX' in dec:
            print(f"FOUND with timing key at {key_start}: {dec}")
        # CBC with payload[:16] as IV
        cipher = AES.new(key, AES.MODE_CBC, iv=payload[:16])
        dec = cipher.decrypt(payload[16:])
        if b'MythX' in dec:
            print(f"FOUND CBC with timing key at {key_start}: {dec}")
    except:
        pass

# =========================================================
# LAST RESORT: Let me look at the entire 2MB memory dump
# for ANY AES-compatible pattern: 
# Try the payload.bin decrypted message as a pointer
# The 64-byte payload decrypted with SHA256(password) gives:
# IV (16 bytes) + "nice_try_but_keep_looking" + padding
# What if the IV contains a pointer to the real flag location?
# =========================================================
print("\n\n=== ANALYZE DECRYPTED PAYLOAD STRUCTURE ===")
cipher = AES.new(key_sha256, AES.MODE_CBC, iv=payload[:16])
dec_payload = cipher.decrypt(payload[16:])
print(f"Decrypted payload: {dec_payload}")
print(f"Hex: {dec_payload.hex()}")

# The IV itself:
iv_data = payload[:16]
print(f"\nIV (first 16 bytes of payload): {iv_data.hex()}")

# What values are in the IV?
import struct
vals = struct.unpack('>IIII', iv_data)
print(f"IV as 4 uint32s: {vals}")
print(f"IV as 4 uint32s hex: {[hex(v) for v in vals]}")

vals16 = struct.unpack('>8H', iv_data)
print(f"IV as 8 uint16s: {vals16}")

# FYI: f184376b 295ff909 723748c7 865e7e62
# Could be memory offsets?
for v in vals:
    if v < len(mem_data):
        ctx = mem_data[v:v+32]
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
        print(f"  mem[{hex(v)}]: {printable}")

# =========================================================
# Let me try: decrypt the WHOLE memory dump with AES-CTR mode
# using the SHA256 key and different nonces
# =========================================================
print("\n\n=== AES-CTR FULL MEMORY SCAN ===")
from Crypto.Cipher import AES
from Crypto.Util import Counter

# Try AES-CTR with nonce = 0
for key_candidate in [key_sha256, timing_key]:
    ctr = Counter.new(128, initial_value=0)
    cipher = AES.new(key_candidate, AES.MODE_CTR, counter=ctr)
    # Decrypt just first 1000 bytes
    dec = cipher.decrypt(mem_data[:1000])
    ascii_s = re.findall(rb'MythX\{[^\}]+\}', dec)
    if ascii_s:
        print(f"  FOUND in CTR: {ascii_s}")
    ascii_s = re.findall(rb'[\x20-\x7e]{10,}', dec)
    if ascii_s:
        print(f"  CTR first 1000: {ascii_s[:5]}")
    
    # Try CTR with nonce from payload
    ctr = Counter.new(128, initial_value=int.from_bytes(payload[:16], 'big'))
    cipher = AES.new(key_candidate, AES.MODE_CTR, counter=ctr)
    dec = cipher.decrypt(mem_data[:1000])
    ascii_s = re.findall(rb'MythX\{[^\}]+\}', dec)
    if ascii_s:
        print(f"  FOUND CTR (payload nonce): {ascii_s}")
