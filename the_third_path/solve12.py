from scapy.all import rdpcap, DNS, DNSQR, IP, UDP, Raw, Ether
import hashlib
import re
from Crypto.Cipher import AES

packets = rdpcap("capture_og0oXNg.pcap")
dns_packets = [pkt for pkt in packets if pkt.haslayer(DNS) and pkt.haslayer(DNSQR)]

with open("memory_IcOZWTs.dmp", "rb") as f:
    mem_data = f.read()

password = b"Rabb1tH0le123!"
key_sha256 = hashlib.sha256(password).digest()

timestamps = [float(pkt.time) for pkt in dns_packets]
deltas = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

# =========================================================
# Let me look at this from a COMPLETELY different angle.
# 
# The memory dump is 2MB of near-max entropy = ENCRYPTED.
# The password Rabb1tH0le123! was found in memory.
# The payload.bin (64 bytes) decrypts to a decoy pointer.
#
# But what if the WHOLE 2MB memory dump is AES-encrypted
# and needs to be decrypted? The 2MB is exactly 2^21.
# AES-CBC would need an IV.
#
# The timing data tells us the IV? Or some other parameter?
#
# Let me try the FULL memory dump decryption.
# =========================================================

print("=== FULL MEMORY DECRYPTION ===")
print(f"Memory size: {len(mem_data)}")
print(f"AES key (SHA256/pw): {key_sha256.hex()}")

# AES-CBC IV=0
cipher = AES.new(key_sha256, AES.MODE_CBC, iv=b'\x00'*16)
dec = cipher.decrypt(mem_data)
flags = re.findall(rb'MythX\{[^\}]+\}', dec)
print(f"CBC IV=0 flags: {flags}")
if not flags:
    # Check for printable strings near decoy area
    strings = re.findall(rb'[\x20-\x7e]{15,}', dec)
    print(f"Long strings: {len(strings)}")
    for s in strings[:10]:
        print(f"  {s}")

# AES-CBC IV from payload
cipher = AES.new(key_sha256, AES.MODE_CBC, iv=bytes.fromhex("f184376b295ff909723748c7865e7e62"))
dec = cipher.decrypt(mem_data)
flags = re.findall(rb'MythX\{[^\}]+\}', dec)
print(f"\nCBC IV=payload flags: {flags}")
if not flags:
    strings = re.findall(rb'[\x20-\x7e]{15,}', dec)
    print(f"Long strings: {len(strings)}")
    for s in strings[:10]:
        print(f"  {s}")

# AES-ECB (full memory)
cipher = AES.new(key_sha256, AES.MODE_ECB)
dec = cipher.decrypt(mem_data)
flags = re.findall(rb'MythX\{[^\}]+\}', dec)
print(f"\nECB flags: {flags}")
if not flags:
    strings = re.findall(rb'[\x20-\x7e]{15,}', dec)
    print(f"Long strings: {len(strings)}")
    for s in strings[:10]:
        print(f"  {s}")

# AES-CTR with nonce 0
from Crypto.Util import Counter
ctr = Counter.new(128, initial_value=0)
cipher = AES.new(key_sha256, AES.MODE_CTR, counter=ctr)
dec = cipher.decrypt(mem_data)
flags = re.findall(rb'MythX\{[^\}]+\}', dec)
print(f"\nCTR nonce=0 flags: {flags}")
if not flags:
    strings = re.findall(rb'[\x20-\x7e]{15,}', dec)
    print(f"Long strings: {len(strings)}")
    for s in strings[:10]:
        print(f"  {s}")

# =========================================================
# Try MD5 as key
# =========================================================
key_md5 = hashlib.md5(password).digest()

cipher = AES.new(key_md5, AES.MODE_ECB)
dec = cipher.decrypt(mem_data)
flags = re.findall(rb'MythX\{[^\}]+\}', dec)
print(f"\nMD5 ECB flags: {flags}")

cipher = AES.new(key_md5, AES.MODE_CBC, iv=b'\x00'*16)
dec = cipher.decrypt(mem_data)
flags = re.findall(rb'MythX\{[^\}]+\}', dec)
print(f"MD5 CBC IV=0 flags: {flags}")

# =========================================================
# KEY DERIVATION: What if the key is derived from the password
# using PBKDF2 or some other KDF?
# =========================================================
print("\n=== PBKDF2 KEY DERIVATION ===")
import hashlib

# PBKDF2 with various salts
for salt in [b'salt', b'', b'MythX', password, b'\x00'*8]:
    key = hashlib.pbkdf2_hmac('sha256', password, salt, 100000, 32)
    cipher = AES.new(key, AES.MODE_ECB)
    dec = cipher.decrypt(mem_data[:256])
    if b'MythX' in dec:
        print(f"FOUND with PBKDF2(salt={salt}): {dec}")
    
    cipher = AES.new(key, AES.MODE_CBC, iv=b'\x00'*16)
    dec = cipher.decrypt(mem_data[:256])
    if b'MythX' in dec:
        print(f"FOUND with PBKDF2-CBC(salt={salt}): {dec}")

# =========================================================
# What about the Fernet or other encryption?
# Or just simple XOR with the SHA256 key repeated?
# =========================================================
print("\n=== XOR WITH KEY ===")
# XOR entire memory with SHA256 key repeated
xor_dec = bytes(mem_data[i] ^ key_sha256[i % 32] for i in range(len(mem_data)))
flags = re.findall(rb'MythX\{[^\}]+\}', xor_dec)
print(f"XOR SHA256 flags: {flags}")
if flags:
    for f in flags:
        print(f"  {f}")

# XOR with password directly
xor_dec2 = bytes(mem_data[i] ^ password[i % len(password)] for i in range(len(mem_data)))
flags = re.findall(rb'MythX\{[^\}]+\}', xor_dec2)
print(f"XOR password flags: {flags}")
if flags:
    for f in flags:
        print(f"  {f}")

# XOR with MD5 key
xor_dec3 = bytes(mem_data[i] ^ key_md5[i % 16] for i in range(len(mem_data)))
flags = re.findall(rb'MythX\{[^\}]+\}', xor_dec3)
print(f"XOR MD5 flags: {flags}")
if flags:
    for f in flags:
        print(f"  {f}")

# =========================================================
# TRY: RC4 encryption with the password
# =========================================================
print("\n=== RC4 ===")
from Crypto.Cipher import ARC4

cipher = ARC4.new(password)
dec = cipher.decrypt(mem_data[:10000])
flags = re.findall(rb'MythX\{[^\}]+\}', dec)
print(f"RC4(password) flags: {flags}")
if not flags:
    strings = re.findall(rb'[\x20-\x7e]{10,}', dec[:2000])
    if strings:
        print(f"RC4 strings: {strings[:10]}")

cipher = ARC4.new(key_sha256)
dec = cipher.decrypt(mem_data[:10000])
flags = re.findall(rb'MythX\{[^\}]+\}', dec)
print(f"RC4(sha256) flags: {flags}")
if not flags:
    strings = re.findall(rb'[\x20-\x7e]{10,}', dec[:2000])
    if strings:
        print(f"RC4/sha256 strings: {strings[:10]}")

# =========================================================
# WHAT IF: The challenge has a PNG at offset 925702?
# Earlier scan found PNG signature there.
# =========================================================
print("\n\n=== EXTRACT PNG ===")
png_start = mem_data.find(b'\x89PNG')
if png_start >= 0:
    print(f"PNG found at offset {png_start}")
    # Find PNG end (IEND chunk)
    png_end = mem_data.find(b'IEND', png_start)
    if png_end >= 0:
        png_end += 8  # IEND chunk is 12 bytes (4 len + 4 type + 4 CRC)
        print(f"PNG IEND at offset {png_end}")
        png_data = mem_data[png_start:png_end]
        print(f"PNG size: {len(png_data)} bytes")
        with open("extracted.png", "wb") as f:
            f.write(png_data)
        print("Saved to extracted.png")
    else:
        print("No IEND found, saving first 10KB")
        with open("extracted.png", "wb") as f:
            f.write(mem_data[png_start:png_start+10240])

# =========================================================
# CHECK ALL ZIP FILES IN MEMORY
# =========================================================
print("\n\n=== CHECK ZIP FILES ===")
import io
import zipfile

zip_positions = [m.start() for m in re.finditer(b'\x50\x4b\x03\x04', mem_data)]
print(f"ZIP local file headers found at: {zip_positions[:10]}")

for pos in zip_positions[:5]:
    # Try to parse ZIP
    # Look for end of central directory
    chunk = mem_data[pos:pos+10000]
    try:
        zf = zipfile.ZipFile(io.BytesIO(chunk))
        print(f"  Valid ZIP at {pos}: {zf.namelist()}")
        for name in zf.namelist():
            content = zf.read(name)
            print(f"    {name}: {content[:200]}")
    except:
        pass

# =========================================================
# Let me look for the string "flag" or "real" or "true" in memory
# =========================================================
print("\n\n=== SEARCH FOR ADDITIONAL STRINGS ===")
for pattern in [b'real', b'true', b'hidden', b'secret', b'covert', b'third', b'path', b'flag{', b'FLAG{', b'MythX', b'the_third', b'third_path']:
    positions = [m.start() for m in re.finditer(pattern, mem_data, re.IGNORECASE)]
    if positions:
        print(f"  '{pattern.decode()}' at: {positions[:5]}")
        for p in positions[:3]:
            ctx = mem_data[max(0,p-20):p+len(pattern)+40]
            text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
            print(f"    {text}")
