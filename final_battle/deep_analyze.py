from PIL import Image
import numpy as np

# The hint says "transparency of the Titan's profile" - check for alpha channels
# and also look at LSB more carefully

# Check if the hidden_image has any alpha channel data originally
img_hidden_rgba = Image.open('hidden_image.png')
print(f"hidden_image original mode: {img_hidden_rgba.mode}")

img_iron_rgba = Image.open('ironman.png')
print(f"ironman original mode: {img_iron_rgba.mode}")

# Load as RGB
img1 = Image.open('ironman.png').convert('RGB')
img2 = Image.open('hidden_image.png').convert('RGB')

arr1 = np.array(img1)
arr2 = np.array(img2)

# Check LSB plane more carefully - extract just the R channel LSB
for name, arr in [('ironman', arr1), ('hidden', arr2)]:
    # Extract LSB of each channel
    for ch_idx, ch_name in [(0, 'R'), (1, 'G'), (2, 'B')]:
        lsb = (arr[:, :, ch_idx] & 1) * 255
        # Check if LSB contains something meaningful
        nonzero_pct = np.count_nonzero(lsb) / lsb.size * 100
        print(f"{name} {ch_name} LSB: {nonzero_pct:.1f}% nonzero")
    
    # Extract LSB bits as binary string (R channel)
    lsb_bits = (arr[:, :, 0] & 1).flatten()
    # Convert first 1000 bits to bytes
    byte_data = bytearray()
    for i in range(0, min(8000, len(lsb_bits)), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | lsb_bits[i + j]
        byte_data.append(byte)
    
    # Check for readable text
    text = byte_data[:100]
    printable = sum(1 for b in text if 32 <= b <= 126)
    print(f"{name} LSB text readable: {printable}/100 chars printable")
    print(f"  First 50 bytes: {bytes(text[:50])}")
    print()

# Now check the XOR result
xor_12 = np.bitwise_xor(arr1, arr2)

# Extract text from XOR if there is one
# Check if XOR creates a visible pattern
# Look at specific color channels
for ch_idx, ch_name in [(0, 'R'), (1, 'G'), (2, 'B')]:
    unique = np.unique(xor_12[:, :, ch_idx])
    print(f"XOR {ch_name} channel: {len(unique)} unique values, range [{unique.min()}-{unique.max()}]")

# Check if there's a pattern in specific bit planes (not just LSB)
for bit in range(8):
    plane = ((xor_12[:, :, 0] >> bit) & 1) * 255
    nonzero_pct = np.count_nonzero(plane) / plane.size * 100
    print(f"XOR R bit {bit}: {nonzero_pct:.1f}% set")

# Save enhanced XOR image (multiply by some factor for visibility)
enhanced = np.clip(xor_12.astype(np.int16) * 10, 0, 255).astype(np.uint8)
Image.fromarray(enhanced).save('xor_enhanced.png')
print("\nSaved xor_enhanced.png")

# The AVIF image - check its LSB too
img3 = Image.open('snap_layer1.avif').convert('RGB')
arr3 = np.array(img3)
print(f"\nAVIF dimensions: {arr3.shape}")

# Extract LSB from AVIF
lsb_bits_avif = (arr3[:, :, 0] & 1).flatten()
byte_data_avif = bytearray()
for i in range(0, min(8000, len(lsb_bits_avif)), 8):
    byte = 0
    for j in range(8):
        byte = (byte << 1) | lsb_bits_avif[i + j]
    byte_data_avif.append(byte)
text_avif = byte_data_avif[:100]
printable_avif = sum(1 for b in text_avif if 32 <= b <= 126)
print(f"AVIF LSB text readable: {printable_avif}/100 chars printable")
print(f"  First 50 bytes: {bytes(text_avif[:50])}")

# Also try all RGB LSB combined
for name, arr in [('ironman', arr1), ('hidden', arr2), ('avif', arr3)]:
    lsb_all = []
    flat_r = (arr[:, :, 0] & 1).flatten()
    flat_g = (arr[:, :, 1] & 1).flatten()  
    flat_b = (arr[:, :, 2] & 1).flatten()
    
    # Try interleaved R,G,B
    for i in range(min(len(flat_r), 10000)):
        lsb_all.extend([flat_r[i], flat_g[i], flat_b[i]])
    
    byte_data2 = bytearray()
    for i in range(0, min(8000, len(lsb_all)), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | lsb_all[i + j]
        byte_data2.append(byte)
    
    text2 = byte_data2[:50]
    printable2 = sum(1 for b in text2 if 32 <= b <= 126)
    print(f"\n{name} RGB-interleaved LSB: {printable2}/50 printable")
    print(f"  First 50 bytes: {bytes(text2[:50])}")
