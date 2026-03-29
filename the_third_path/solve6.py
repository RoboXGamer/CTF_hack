import hashlib
import re

with open("memory_IcOZWTs.dmp", "rb") as f:
    mem_data = f.read()

payload = bytes.fromhex("f184376b295ff909723748c7865e7e623ba4bb0bbde13f3c131faafdaff3aef6651197dc76d110067dc3d022a90af7dbf36e198543bfe7cc75c9ce329036ddba")
password = b"Rabb1tH0le123!"

print(f"Payload ({len(payload)} bytes): {payload.hex()}")
print(f"Password: {password.decode()}")

# Try various decryption methods

# 1. Simple XOR with password
print("\n=== XOR with password (repeating) ===")
xored = bytes(payload[i] ^ password[i % len(password)] for i in range(len(payload)))
print(f"Result: {xored}")
print(f"Hex: {xored.hex()}")

# 2. AES decryption (various modes)
# AES-256 needs 32-byte key, AES-128 needs 16-byte key
# Derive key from password via SHA256
key_sha256 = hashlib.sha256(password).digest()
key_md5 = hashlib.md5(password).digest()
print(f"\nSHA256 key: {key_sha256.hex()}")
print(f"MD5 key: {key_md5.hex()}")

# Need pycryptodome for AES
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    
    # AES-ECB with SHA256 key
    print("\n=== AES-ECB with SHA256 key ===")
    cipher = AES.new(key_sha256, AES.MODE_ECB)
    decrypted = cipher.decrypt(payload)
    print(f"Decrypted: {decrypted}")
    print(f"Hex: {decrypted.hex()}")
    
    # AES-CBC with SHA256 key, IV = first 16 bytes
    print("\n=== AES-CBC with SHA256 key, IV from payload ===")
    iv = payload[:16]
    ct = payload[16:]
    cipher = AES.new(key_sha256, AES.MODE_CBC, iv=iv)
    decrypted = cipher.decrypt(ct)
    print(f"Decrypted: {decrypted}")
    
    # AES-CBC with SHA256 key, IV = zeros
    print("\n=== AES-CBC with SHA256 key, IV=0 ===")
    iv = b'\x00' * 16
    cipher = AES.new(key_sha256, AES.MODE_CBC, iv=iv)
    decrypted = cipher.decrypt(payload)
    print(f"Decrypted: {decrypted}")
    
    # AES-128-ECB with MD5 key
    print("\n=== AES-128-ECB with MD5 key ===")
    cipher = AES.new(key_md5, AES.MODE_ECB)
    decrypted = cipher.decrypt(payload)
    print(f"Decrypted: {decrypted}")
    
    # AES-128-CBC with MD5 key
    print("\n=== AES-128-CBC with MD5 key, IV from payload ===")
    iv = payload[:16]
    ct = payload[16:]
    cipher = AES.new(key_md5, AES.MODE_CBC, iv=iv)
    decrypted = cipher.decrypt(ct)
    print(f"Decrypted: {decrypted}")
    
    # AES-128-CBC with MD5 key, IV=0
    print("\n=== AES-128-CBC with MD5 key, IV=0 ===")
    iv = b'\x00' * 16
    cipher = AES.new(key_md5, AES.MODE_CBC, iv=iv)
    decrypted = cipher.decrypt(payload)
    print(f"Decrypted: {decrypted}")
    
    # Try password directly as key (padded/truncated)
    key_direct_16 = password[:16].ljust(16, b'\x00')
    key_direct_32 = password[:32].ljust(32, b'\x00')
    
    print("\n=== AES-128-ECB with password direct (padded) ===")
    cipher = AES.new(key_direct_16, AES.MODE_ECB)
    decrypted = cipher.decrypt(payload)
    print(f"Decrypted: {decrypted}")
    
    print("\n=== AES-256-ECB with password direct (padded) ===")
    cipher = AES.new(key_direct_32, AES.MODE_ECB)
    decrypted = cipher.decrypt(payload)
    print(f"Decrypted: {decrypted}")

    # AES-256-CBC with password direct, IV=0
    print("\n=== AES-256-CBC with password direct (padded), IV=0 ===")
    cipher = AES.new(key_direct_32, AES.MODE_CBC, iv=b'\x00'*16)
    decrypted = cipher.decrypt(payload)
    print(f"Decrypted: {decrypted}")
    
    # AES-128-CBC with password direct, IV=0
    print("\n=== AES-128-CBC with password direct (padded), IV=0 ===")
    cipher = AES.new(key_direct_16, AES.MODE_CBC, iv=b'\x00'*16)
    decrypted = cipher.decrypt(payload)
    print(f"Decrypted: {decrypted}")
    
except ImportError:
    print("pycryptodome not installed, trying other methods")

# 3. Also look for more strings in memory around the password location
print("\n\n=== Context around password in memory ===")
pwd_pos = mem_data.find(b"Rabb1tH0le123!")
print(f"Password found at offset: {pwd_pos}")
if pwd_pos >= 0:
    context = mem_data[pwd_pos - 200:pwd_pos + 200]
    # Extract all printable strings
    strings = re.findall(rb'[\x20-\x7e]{4,}', context)
    for s in strings:
        print(f"  {s}")
    # Also show raw hex around it  
    print(f"\nRaw bytes around password:")
    for offset in range(pwd_pos - 100, pwd_pos + 100, 32):
        chunk = mem_data[offset:offset+32]
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"  {offset:#010x}: {chunk.hex()}")
        print(f"             {printable}")

# Look for AES-related strings and encryption mode hints
print("\n\n=== Crypto-related strings in memory ===")
for pattern in [b'AES', b'CBC', b'ECB', b'CTR', b'GCM', b'iv=', b'IV=', b'nonce', b'key=', b'Crypt', b'encrypt', b'decrypt', b'openssl', b'Salted']:
    positions = [m.start() for m in re.finditer(re.escape(pattern), mem_data, re.IGNORECASE)]
    if positions:
        print(f"  '{pattern.decode()}' at: {positions}")
        for p in positions[:3]:
            ctx = mem_data[max(0,p-30):p+len(pattern)+30]
            ctx_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
            print(f"    Context: {ctx_str}")
