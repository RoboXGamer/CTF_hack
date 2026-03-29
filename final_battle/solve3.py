from PIL import Image
import numpy as np

# Load all three images at same dimensions
img1 = Image.open('ironman.png').convert('RGB')
img2 = Image.open('hidden_image.png').convert('RGB')
img3 = Image.open('snap_layer1.avif').convert('RGB').resize((1280, 720))

arr1 = np.array(img1)
arr2 = np.array(img2)
arr3 = np.array(img3)

# "Overlap the fallen" = XOR all three
xor_all = np.bitwise_xor(np.bitwise_xor(arr1, arr2), arr3)
Image.fromarray(xor_all).save('xor_all_three.png')

# Also try addition/subtraction-based blending
# Maybe "overlap" means something like image blending
blend_add = np.clip(arr1.astype(np.int16) + arr2.astype(np.int16) + arr3.astype(np.int16), 0, 255).astype(np.uint8)
Image.fromarray(blend_add).save('blend_add.png')

# Try subtracting
diff_12 = np.abs(arr1.astype(np.int16) - arr2.astype(np.int16)).astype(np.uint8)
Image.fromarray(diff_12).save('diff_ironman_hidden.png')

diff_all = np.abs(arr1.astype(np.int16) - arr2.astype(np.int16) - arr3.astype(np.int16)).clip(0,255).astype(np.uint8)

# Maybe the flag is in specific color channels or planes
# Let's check if there's a pattern when we look at specific bits of XOR
# Enhance different bit planes
for bit in range(4):  # Lower 4 bits
    plane_r = ((xor_all[:,:,0] >> bit) & 1) * 255
    plane_g = ((xor_all[:,:,1] >> bit) & 1) * 255
    plane_b = ((xor_all[:,:,2] >> bit) & 1) * 255
    combined = np.stack([plane_r, plane_g, plane_b], axis=2).astype(np.uint8)
    Image.fromarray(combined).save(f'xor_all_bit{bit}.png')

print("All output images saved")

# Also check: maybe the hidden image IS a different size and should be XOR'd differently
# Let's check for text in all images using OCR-like approach
# Actually, let's look at the raw bytes of the original file more carefully

# Search for mythx in the entire original file
f = open('The_Snap.png', 'rb')
original = f.read()
f.close()

for kw in [b'mythx', b'myth', b'flag{', b'FLAG', b'key=', b'password']:
    positions = []
    start = 0
    while True:
        pos = original.find(kw, start)
        if pos == -1:
            break
        positions.append(pos)
        start = pos + 1
    if positions:
        print(f"'{kw.decode(errors='replace')}' found at: {positions}")
        for p in positions:
            context = original[max(0,p-20):p+50]
            print(f"  Context: {context}")

# Also search in ironman.png
f = open('ironman.png', 'rb')
iron_raw = f.read()
f.close()

for kw in [b'mythx', b'myth', b'flag{', b'FLAG', b'key=', b'password', b'stego', b'steghide']:
    positions = []
    start = 0
    while True:
        pos = iron_raw.find(kw, start)
        if pos == -1:
            break
        positions.append(pos)
        start = pos + 1
    if positions:
        print(f"ironman '{kw.decode(errors='replace')}' at: {positions}")
        for p in positions:
            context = iron_raw[max(0,p-20):p+50]
            print(f"  Context: {context}")

# Search in hidden_image.png 
f = open('hidden_image.png', 'rb')
hidden_raw = f.read()
f.close()

for kw in [b'mythx', b'myth', b'flag{', b'FLAG', b'key=', b'password', b'Hint', b'Balance']:
    positions = []
    start = 0
    while True:
        pos = hidden_raw.find(kw, start)
        if pos == -1:
            break
        positions.append(pos)
        start = pos + 1
    if positions:
        print(f"hidden '{kw.decode(errors='replace')}' at: {positions}")
        for p in positions:
            context = hidden_raw[max(0,p-20):p+50]
            print(f"  Context: {context}")
