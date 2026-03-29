import struct
import zlib

f = open('hidden_image.png', 'rb')
data = f.read()
f.close()

# The iCCP chunk at offset... let's find it properly
pos = 8
while pos < len(data):
    length = struct.unpack('>I', data[pos:pos+4])[0]
    chunk_type = data[pos+4:pos+8].decode('ascii', errors='replace')
    chunk_data = data[pos+8:pos+8+length]
    
    if chunk_type == 'iCCP':
        print(f"iCCP chunk at {pos}, size={length}")
        # iCCP format: profile_name\0 compression_method compressed_profile
        null_pos = chunk_data.index(b'\x00')
        profile_name = chunk_data[:null_pos].decode()
        compression = chunk_data[null_pos+1]
        compressed_data = chunk_data[null_pos+2:]
        print(f"  Profile name: '{profile_name}'")
        print(f"  Compression method: {compression}")
        print(f"  Compressed data size: {len(compressed_data)}")
        
        # Decompress
        try:
            decompressed = zlib.decompress(compressed_data)
            print(f"  Decompressed size: {len(decompressed)}")
            print(f"  Header: {decompressed[:32].hex()}")
            
            # Check if it's a PNG
            if decompressed[:8] == b'\x89PNG\r\n\x1a\n':
                print("  IT'S A PNG! Saving as thanos.png")
                with open('thanos.png', 'wb') as out:
                    out.write(decompressed)
            elif decompressed[:4] == b'PK\x03\x04':
                print("  IT'S A ZIP!")
                with open('hidden_iccp.zip', 'wb') as out:
                    out.write(decompressed)
            else:
                # Save raw and check
                with open('iccp_data.bin', 'wb') as out:
                    out.write(decompressed)
                print(f"  First 100 bytes: {decompressed[:100]}")
                
                # Search for PNG inside
                png_pos = decompressed.find(b'\x89PNG\r\n\x1a\n')
                if png_pos >= 0:
                    print(f"  Found PNG at offset {png_pos}!")
                    with open('thanos.png', 'wb') as out:
                        out.write(decompressed[png_pos:])
                
                # Search for text
                for kw in [b'mythx', b'flag', b'thanos', b'Thanos']:
                    kw_pos = decompressed.find(kw)
                    if kw_pos >= 0:
                        print(f"  Found '{kw.decode()}' at {kw_pos}: {decompressed[kw_pos:kw_pos+50]}")
        except Exception as e:
            print(f"  Decompress error: {e}")
            # Maybe it's not zlib, save raw
            with open('iccp_raw.bin', 'wb') as out:
                out.write(compressed_data)
    
    pos += 12 + length
    if chunk_type == 'IEND':
        break

# Also: the PNG at offset 68 in hidden_image.png - that's within the iCCP chunk data
# Let me extract directly
png_sig = b'\x89PNG\r\n\x1a\n'
all_png = [i for i in range(len(data)) if data[i:i+8] == png_sig]
print(f"\nAll PNG signatures in hidden_image.png: {all_png}")

for idx, png_offset in enumerate(all_png):
    if png_offset == 0:
        continue  # skip the main image
    print(f"\nExtracting PNG at offset {png_offset}...")
    # Find the IEND for this PNG
    iend_search = data.find(b'IEND', png_offset + 8)
    if iend_search >= 0:
        end = iend_search + 8  # IEND type(4) + CRC(4)
        png_data = data[png_offset:end]
        fname = f'extracted_png_{idx}.png'
        with open(fname, 'wb') as out:
            out.write(png_data)
        print(f"  Saved as {fname}, size={len(png_data)}")
        
        # Check dimensions
        ihdr_pos = png_data.find(b'IHDR')
        if ihdr_pos >= 0:
            w = struct.unpack('>I', png_data[ihdr_pos+4:ihdr_pos+8])[0]
            h = struct.unpack('>I', png_data[ihdr_pos+8:ihdr_pos+12])[0]
            bd = png_data[ihdr_pos+12]
            ct = png_data[ihdr_pos+13]
            print(f"  Dimensions: {w}x{h}, bit_depth={bd}, color_type={ct}")
