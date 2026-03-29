from PIL import Image
import numpy as np

img1 = Image.open('ironman.png').convert('RGB')
img2 = Image.open('hidden_image.png').convert('RGB')
arr1 = np.array(img1)
arr2 = np.array(img2)

# Check XOR bit planes
xor_12 = np.bitwise_xor(arr1, arr2)
for bit in range(8):
    plane = ((xor_12[:,:,0] >> bit) & 1) * 255
    pct = np.count_nonzero(plane) / plane.size * 100
    print(f"XOR R bit {bit}: {pct:.1f}%")

# Check if LSB of either image contains readable data (all 3 channels interleaved)
for name, arr in [('ironman', arr1), ('hidden', arr2)]:
    bits = []
    for y in range(arr.shape[0]):
        for x in range(arr.shape[1]):
            for c in range(3):
                bits.append(arr[y, x, c] & 1)
            if len(bits) >= 80000:
                break
        if len(bits) >= 80000:
            break
    
    byte_data = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        byte_data.append(byte)
    
    # Check for 'mythx' or other flag text
    text = bytes(byte_data)
    if b'mythx' in text:
        idx = text.index(b'mythx')
        print(f"FOUND 'mythx' in {name} LSB at byte {idx}!")
        print(f"  Context: {text[idx:idx+100]}")
    
    printable = sum(1 for b in byte_data[:200] if 32 <= b <= 126)
    print(f"{name} LSB: {printable}/200 printable chars")
    # Print decoded as text
    decoded = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in byte_data[:200])
    print(f"  Text: {decoded[:100]}")

# Now try XOR-then-LSB
xor_bits = []
for y in range(xor_12.shape[0]):
    for x in range(xor_12.shape[1]):
        for c in range(3):
            xor_bits.append(xor_12[y, x, c] & 1)
        if len(xor_bits) >= 80000:
            break
    if len(xor_bits) >= 80000:
        break

byte_data_xor = bytearray()
for i in range(0, len(xor_bits) - 7, 8):
    byte = 0
    for j in range(8):
        byte = (byte << 1) | xor_bits[i + j]
    byte_data_xor.append(byte)

text_xor = bytes(byte_data_xor)
if b'mythx' in text_xor:
    idx = text_xor.index(b'mythx')
    print(f"\nFOUND 'mythx' in XOR LSB at byte {idx}!")
    print(f"  Context: {text_xor[idx:idx+100]}")

decoded_xor = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in byte_data_xor[:200])
print(f"\nXOR LSB text: {decoded_xor[:100]}")
