from scapy.all import rdpcap, DNS, DNSQR
import struct
import re

packets = rdpcap("capture_og0oXNg.pcap")
dns_packets = [pkt for pkt in packets if pkt.haslayer(DNS) and pkt.haslayer(DNSQR)]

timestamps = [float(pkt.time) for pkt in dns_packets]
deltas = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

# The PNG hint says: 600x40 1-bit monochrome (8 aligned)
# 600 pixels wide / 8 bits = 75 bytes per row
# 40 rows
# Total: 75 * 40 = 3000 bytes
# We have 3001 deltas - this matches perfectly!

# Each delta encodes ONE BYTE (not one bit!)
# The timing deviation from 8.09375 gives us a byte value

BASE = 259  # 8.09375 * 32
delta_units = [round(d * 32) for d in deltas]
dev_units = [BASE - u for u in delta_units]

# =========================================================
# THEORY: Each deviation tells us a byte value for the bitmap
# deviation 0 = 0x00 (or 0xFF?)
# deviation > 0 = some byte value
# 
# For a 1-bit monochrome bitmap:
# Each byte represents 8 pixels (1 bit per pixel)
# Total needed: 3000 bytes
# We have 3001 deltas
# =========================================================

# APPROACH 1: Use ALL 3001 delta values as raw bytes
# deviation = BASE - delta_unit, capped to 0-255
print("=== APPROACH 1: Deviation as byte value ===")
raw_bytes = bytearray()
for d in dev_units:
    if d < 0:
        raw_bytes.append(0)  # or 256 + d
    elif d > 255:
        raw_bytes.append(255)
    else:
        raw_bytes.append(d)

# Take first 3000 bytes (skip last one or first one)
bitmap_data = bytes(raw_bytes[:3000])
print(f"Bitmap data length: {len(bitmap_data)}")
print(f"First 75 bytes (row 0): {bitmap_data[:75].hex()}")
print(f"Non-zero bytes: {sum(1 for b in bitmap_data if b != 0)}")

# Create a PNG from this bitmap
import zlib
import io

def create_png_from_1bit(data, width=600, height=40):
    """Create a PNG from 1-bit bitmap data"""
    row_bytes = (width + 7) // 8  # 75 bytes per row
    
    # Create RGBA image data
    raw_data = bytearray()
    for y in range(height):
        raw_data.append(0)  # Filter byte (None)
        row = data[y * row_bytes:(y + 1) * row_bytes]
        for x in range(width):
            byte_idx = x // 8
            bit_idx = 7 - (x % 8)
            if byte_idx < len(row):
                pixel = (row[byte_idx] >> bit_idx) & 1
            else:
                pixel = 0
            # White pixel = 1, Black pixel = 0
            if pixel:
                raw_data.extend([255, 255, 255, 255])  # White
            else:
                raw_data.extend([0, 0, 0, 255])  # Black
    
    # Build PNG
    def png_chunk(chunk_type, data):
        chunk = chunk_type + data
        crc = zlib.crc32(chunk) & 0xFFFFFFFF
        return struct.pack('>I', len(data)) + chunk + struct.pack('>I', crc)
    
    # IHDR
    ihdr = struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)
    
    # IDAT
    compressed = zlib.compress(bytes(raw_data))
    
    png = b'\x89PNG\r\n\x1a\n'
    png += png_chunk(b'IHDR', ihdr)
    png += png_chunk(b'IDAT', compressed)
    png += png_chunk(b'IEND', b'')
    
    return png

# Save with deviation values
png = create_png_from_1bit(bitmap_data)
with open("bitmap_deviation.png", "wb") as f:
    f.write(png)
print("Saved bitmap_deviation.png")

# APPROACH 2: 0 = white, non-zero = black (inverted)
bitmap_inv = bytes(255 if b == 0 else 0 for b in bitmap_data)
png = create_png_from_1bit(bitmap_inv)
with open("bitmap_deviation_inv.png", "wb") as f:
    f.write(png)
print("Saved bitmap_deviation_inv.png")

# APPROACH 3: delta_units directly as bytes (mod 256)
# 259 mod 256 = 3, so most bytes are 3 (0b00000011)
print("\n=== APPROACH 3: delta_unit mod 256 ===")
raw_mod = bytes([u % 256 for u in delta_units[:3000]])
png = create_png_from_1bit(raw_mod)
with open("bitmap_deltamod.png", "wb") as f:
    f.write(png)
print("Saved bitmap_deltamod.png")

# APPROACH 4: Maybe each delta encodes a SINGLE BIT (not byte)
# 3001 deltas = 3001 bits. But we need 3000 bytes = 24000 bits
# So this doesn't work directly.
# But 3001 bits / 8 ≈ 375 bytes. Not enough.

# APPROACH 5: The deviation value represents the byte directly
# For the normal heartbeat (dev=0), the byte is 0x00
# For non-standard, deviation = byte value
# Since we have exactly 389 groups of non-zero deviations, 
# and we need 3000 bytes, each deviation contributes ONE byte

# Actually wait - reread: "600x40 1-bit monochrome (8 aligned)"
# 3000 bytes * 8 = 24000 bits = 600 * 40 pixels. Perfect!
# Each byte in the bitmap represents 8 pixels.
# 
# With 3001 deltas and 3000 needed bytes:
# Skip first delta (which is unusual at 8.6s) and use the remaining 3000

bitmap2 = bytes(raw_bytes[1:3001])  # skip first
png = create_png_from_1bit(bitmap2)
with open("bitmap_skip1.png", "wb") as f:
    f.write(png)
print("\nSaved bitmap_skip1.png (skip first delta)")

# APPROACH 6: Use the OR-assembled groups
# Each group's byte value AND the number of base heartbeats between groups
# could define the bitmap structure

# APPROACH 7: What if the non-zero deviation means pixel ON (1)
# and zero means pixel OFF (0)?
# Then each delta IS one bit!
# 3001 bits → 375 bytes. Not 3000...

# BUT WAIT - maybe the 1-bit data is per DELTA, not per byte:
# 3001 bits compressed into 375 bytes, forming 3001 pixels
# But 600*40 = 24000, not 3001

# APPROACH 8: Each byte in memory at a specific location IS the bitmap
# The timing gives us WHERE to look
# The PNG says "Missing Data" - the bitmap data is split between 
# the timing channel (network) and memory (RAM)!
# "bridging the network and RAM" = combine both to get the bitmap!

# What if we need to XOR timing bytes with memory bytes at specific offsets
# to reconstruct the bitmap?
print("\n=== APPROACH 8: XOR timing with memory ===")

with open("memory_IcOZWTs.dmp", "rb") as f:
    mem_data = f.read()

# 3000 bytes needed. Timing gives 3001 dev values.
# Memory has 2MB. Maybe the bitmap is at a specific offset in memory
# and the timing deviations are the XOR key.

# The PNG was at offset 925702 in memory with IEND at 931272
# So after the PNG (5570 bytes), there might be the bitmap data
# PNG ends at 931272. Let's look after it.
bitmap_start = 931272
bitmap_candidate = mem_data[bitmap_start:bitmap_start+3000]
print(f"Memory after PNG ({bitmap_start}): {bitmap_candidate[:50].hex()}")

# XOR this with timing deviations
xor_bitmap = bytes(bitmap_candidate[i] ^ (raw_bytes[i] & 0xFF) for i in range(3000))
png = create_png_from_1bit(xor_bitmap)
with open("bitmap_xor_after_png.png", "wb") as f:
    f.write(png)
print("Saved bitmap_xor_after_png.png")

# Also try: memory just before the PNG
bitmap_before = mem_data[bitmap_start - 3000:bitmap_start]
xor_bitmap2 = bytes(bitmap_before[i] ^ (raw_bytes[i] & 0xFF) for i in range(3000))
png = create_png_from_1bit(xor_bitmap2)
with open("bitmap_xor_before_png.png", "wb") as f:
    f.write(png)
print("Saved bitmap_xor_before_png.png")

# Try memory at offset 0
xor_bitmap3 = bytes(mem_data[i] ^ (raw_bytes[i] & 0xFF) for i in range(3000))
png = create_png_from_1bit(xor_bitmap3)
with open("bitmap_xor_mem0.png", "wb") as f:
    f.write(png)
print("Saved bitmap_xor_mem0.png")

# Try at various offsets looking for one that produces readable text
print("\n=== SCANNING MEMORY FOR BITMAP MATCH ===")
# The bitmap should show text (flag), so when rendered correctly
# it should have structured pixel patterns
# Let's look for the offset where XOR gives us a reasonable ratio
# of 0 and 1 bits (for text, roughly 10-30% of pixels are ON)

best_offsets = []
for offset in range(0, len(mem_data) - 3000, 100):
    chunk = mem_data[offset:offset+3000]
    xored = bytes(chunk[i] ^ (raw_bytes[i] & 0xFF) for i in range(3000))
    ones = sum(bin(b).count('1') for b in xored)
    total = 3000 * 8
    ratio = ones / total
    if 0.05 < ratio < 0.35:  # Reasonable for text
        best_offsets.append((offset, ratio, ones))

best_offsets.sort(key=lambda x: abs(x[1] - 0.15))
print(f"Best offset candidates (sorted by ratio ≈ 0.15):")
for offset, ratio, ones in best_offsets[:20]:
    print(f"  offset={offset}, ratio={ratio:.3f}, ones={ones}")

# Generate PNG for top candidates
for i, (offset, ratio, ones) in enumerate(best_offsets[:5]):
    chunk = mem_data[offset:offset+3000]
    xored = bytes(chunk[j] ^ (raw_bytes[j] & 0xFF) for j in range(3000))
    png = create_png_from_1bit(xored)
    with open(f"bitmap_candidate_{i}_{offset}.png", "wb") as f:
        f.write(png)
    print(f"  Saved bitmap_candidate_{i}_{offset}.png")
