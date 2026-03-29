import struct, zlib

f = open('hidden_image.png', 'rb')
data = f.read()
f.close()

# The PNG at offset 68 is inside the iCCP chunk
# But the iCCP chunk holds compressed data - maybe the PNG visible at offset 68
# is actually the raw bytes that HAPPEN to contain a PNG signature
# because the iCCP data was crafted that way

# Let me look at what's actually at offset 68
print(f"Bytes 60-80: {data[60:80].hex()}")
print(f"Bytes 68-100: {data[68:100]}")

# Parse the file properly - offset 68 is inside the iCCP chunk
# iCCP starts at pos=33, length=823890
# chunk header: 4 bytes length + 4 bytes type = 33+8 = 41
# iCCP data starts at 41
# iCCP format: name\0compression_byte\0compressed_data
# Let's see what name is
iccp_start = 41
null = data.index(b'\x00', iccp_start)
name = data[iccp_start:null]
print(f"iCCP name: {name}")
print(f"Compression byte: {data[null+1]}")
print(f"Compressed data starts at: {null+2}")
print(f"So PNG at 68 is inside compressed data at relative offset: {68 - (null+2)}")

# The key insight: the iCCP compressed data STARTS with a zlib-compressed PNG
# When decompressed, it gives us a PNG
# BUT the PNG was corrupted in extraction because we're cutting in wrong place

# Let me try a different approach: decompress the iCCP and properly save
compressed = data[null+2:41+823890]
print(f"Compressed data length: {len(compressed)}")

try:
    decompressed = zlib.decompress(compressed)
    print(f"Decompressed length: {len(decompressed)}")
    # First bytes
    print(f"First 50 hex: {decompressed[:50].hex()}")
    # The decompressed starts with 78 da - that's ANOTHER zlib header!
    if decompressed[:2] == b'\x78\xda' or decompressed[:2] == b'\x78\x9c':
        print("Decompressed data starts with ZLIB header - double compressed!")
        inner = zlib.decompress(decompressed)
        print(f"Inner decompressed: {len(inner)} bytes")
        print(f"Inner header: {inner[:32].hex()}")
        if inner[:8] == b'\x89PNG\r\n\x1a\n':
            with open('thanos.png', 'wb') as out:
                out.write(inner)
            print("SAVED thanos.png!")
    else:
        # Find PNG start
        png_pos = decompressed.find(b'\x89PNG\r\n\x1a\n')
        if png_pos >= 0:
            png_data = decompressed[png_pos:]
            # Find IEND
            iend_pos = png_data.find(b'IEND')
            if iend_pos >= 0:
                png_data = png_data[:iend_pos+8]
            with open('thanos.png', 'wb') as out:
                out.write(png_data)
            print(f"Saved thanos.png ({len(png_data)} bytes)")
            
            # Verify by trying to parse chunks
            pos = 8
            ok = True
            while pos < len(png_data):
                if pos + 8 > len(png_data):
                    print(f"  Truncated at {pos}")
                    ok = False
                    break
                length = struct.unpack('>I', png_data[pos:pos+4])[0]
                ct = png_data[pos+4:pos+8]
                if ct == b'IHDR':
                    w = struct.unpack('>I', png_data[pos+8:pos+12])[0]
                    h = struct.unpack('>I', png_data[pos+12:pos+16])[0]
                    print(f"  {ct.decode()}: {w}x{h}")
                elif ct == b'IDAT':
                    pass
                elif ct == b'IEND':
                    print(f"  IEND found")
                    break
                else:
                    print(f"  Chunk: {ct.decode(errors='replace')} size={length}")
                pos += 12 + length
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
