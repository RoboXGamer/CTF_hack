import struct, zlib
from PIL import Image
import numpy as np

# Method 1: Extract from iCCP decompressed data
f = open('hidden_image.png', 'rb')
data = f.read()
f.close()

pos = 8
while pos < len(data):
    length = struct.unpack('>I', data[pos:pos+4])[0]
    chunk_type = data[pos+4:pos+8].decode('ascii', errors='replace')
    chunk_data = data[pos+8:pos+8+length]
    
    if chunk_type == 'iCCP':
        null_pos = chunk_data.index(b'\x00')
        compressed_data = chunk_data[null_pos+2:]
        decompressed = zlib.decompress(compressed_data)
        
        # Find PNG inside
        png_pos = decompressed.find(b'\x89PNG\r\n\x1a\n')
        if png_pos >= 0:
            with open('thanos_from_iccp.png', 'wb') as out:
                out.write(decompressed[png_pos:])
            print(f"Saved thanos_from_iccp.png ({len(decompressed[png_pos:])} bytes)")
        break
    pos += 12 + length

# Method 2: Already extracted extracted_png_1.png
# Let's verify both work
for fname in ['thanos_from_iccp.png', 'extracted_png_1.png']:
    try:
        img = Image.open(fname)
        print(f"{fname}: {img.size}, mode={img.mode}")
    except Exception as e:
        print(f"{fname}: ERROR - {e}")

# Now load all THREE real images
print("\n=== Loading all 3 images ===")
img_iron = Image.open('ironman.png').convert('RGB')
img_hidden = Image.open('hidden_image.png').convert('RGB')

# Try both extracted Thanos images
for thanos_file in ['thanos_from_iccp.png', 'extracted_png_1.png']:
    try:
        img_thanos = Image.open(thanos_file).convert('RGB')
        print(f"Thanos from {thanos_file}: {img_thanos.size}")
        
        arr_iron = np.array(img_iron)
        arr_hidden = np.array(img_hidden)
        arr_thanos = np.array(img_thanos)
        
        print(f"Shapes: iron={arr_iron.shape}, hidden={arr_hidden.shape}, thanos={arr_thanos.shape}")
        
        if arr_iron.shape == arr_hidden.shape == arr_thanos.shape:
            # XOR all three
            xor_all = np.bitwise_xor(np.bitwise_xor(arr_iron, arr_hidden), arr_thanos)
            Image.fromarray(xor_all).save('xor_three_real.png')
            print("Saved xor_three_real.png")
            
            # Pairwise XORs
            xor_it = np.bitwise_xor(arr_iron, arr_thanos)
            Image.fromarray(xor_it).save('xor_iron_thanos.png')
            
            xor_ht = np.bitwise_xor(arr_hidden, arr_thanos)
            Image.fromarray(xor_ht).save('xor_hidden_thanos.png')
            
            print("Saved pairwise XORs")
            
            # Grayscale blends
            g_iron = np.mean(arr_iron, axis=2)
            g_hidden = np.mean(arr_hidden, axis=2)
            g_thanos = np.mean(arr_thanos, axis=2)
            
            # Various blends of all 3
            for a1, a2, a3, name in [(0.33, 0.33, 0.34, 'equal'),
                                      (0.5, 0.25, 0.25, 'iron_heavy'),
                                      (0.25, 0.5, 0.25, 'hidden_heavy'),
                                      (0.25, 0.25, 0.5, 'thanos_heavy')]:
                blend = (g_iron * a1 + g_hidden * a2 + g_thanos * a3).astype(np.uint8)
                Image.fromarray(blend).save(f'blend3_{name}.png')
            
            # Difference
            diff = np.abs(g_iron - g_thanos)
            diff_norm = ((diff - diff.min()) / (diff.max() - diff.min()) * 255).astype(np.uint8)
            Image.fromarray(diff_norm).save('diff_iron_thanos.png')
            
            diff2 = np.abs(g_hidden - g_thanos)
            diff2_norm = ((diff2 - diff2.min()) / (diff2.max() - diff2.min()) * 255).astype(np.uint8)
            Image.fromarray(diff2_norm).save('diff_hidden_thanos.png')
            
            print("All blend/diff images saved!")
            break
    except Exception as e:
        print(f"Error with {thanos_file}: {e}")
