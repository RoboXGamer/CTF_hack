from PIL import Image
import numpy as np

# Load the two PNG images
print("Loading ironman.png...")
img1 = Image.open('ironman.png').convert('RGB')
print(f"ironman.png: {img1.size}, mode={img1.mode}")

print("Loading hidden_image.png...")
img2 = Image.open('hidden_image.png').convert('RGB')
print(f"hidden_image.png: {img2.size}, mode={img2.mode}")

# Try loading AVIF
try:
    print("Loading snap_layer1.avif...")
    img3 = Image.open('snap_layer1.avif').convert('RGB')
    print(f"snap_layer1.avif: {img3.size}, mode={img3.mode}")
    has_avif = True
except Exception as e:
    print(f"Cannot load AVIF: {e}")
    # Try loading the original file as-is
    try:
        print("Trying The_Snap.png directly...")
        img3 = Image.open('The_Snap.png').convert('RGB')
        print(f"The_Snap.png: {img3.size}, mode={img3.mode}")
        has_avif = True
    except Exception as e2:
        print(f"Cannot load The_Snap.png either: {e2}")
        has_avif = False

# Convert to numpy arrays
arr1 = np.array(img1)
arr2 = np.array(img2)

print(f"\nArray shapes: ironman={arr1.shape}, hidden={arr2.shape}")

# XOR the two PNGs first
xor_12 = np.bitwise_xor(arr1, arr2)
result_12 = Image.fromarray(xor_12)
result_12.save('xor_ironman_hidden.png')
print("Saved xor_ironman_hidden.png")

if has_avif:
    arr3 = np.array(img3)
    print(f"AVIF shape: {arr3.shape}")
    
    # Make sure dimensions match
    if arr3.shape == arr1.shape:
        # XOR all three
        xor_all = np.bitwise_xor(np.bitwise_xor(arr1, arr2), arr3)
        result_all = Image.fromarray(xor_all)
        result_all.save('xor_all_three.png')
        print("Saved xor_all_three.png")
        
        # Also try pairwise XORs
        xor_13 = np.bitwise_xor(arr1, arr3)
        Image.fromarray(xor_13).save('xor_ironman_avif.png')
        print("Saved xor_ironman_avif.png")
        
        xor_23 = np.bitwise_xor(arr2, arr3)
        Image.fromarray(xor_23).save('xor_hidden_avif.png')
        print("Saved xor_hidden_avif.png")
    else:
        print(f"Dimension mismatch! Resizing AVIF from {arr3.shape} to match {arr1.shape}")
        img3_resized = img3.resize(img1.size)
        arr3 = np.array(img3_resized)
        xor_all = np.bitwise_xor(np.bitwise_xor(arr1, arr2), arr3)
        result_all = Image.fromarray(xor_all)
        result_all.save('xor_all_three.png')
        print("Saved xor_all_three.png")

# Also check LSB of each image
print("\n--- LSB Analysis ---")
for name, arr in [('ironman', arr1), ('hidden', arr2)]:
    lsb = (arr & 1) * 255
    Image.fromarray(lsb.astype(np.uint8)).save(f'lsb_{name}.png')
    print(f"Saved lsb_{name}.png")

# Check for text in XOR result
print("\n--- Checking XOR result for patterns ---")
# Look at unique pixel values in XOR
unique_colors = len(np.unique(xor_12.reshape(-1, 3), axis=0))
print(f"Unique colors in XOR result: {unique_colors}")

# Check if mostly black (zeros) with some data
nonzero = np.count_nonzero(xor_12)
total = xor_12.size
print(f"Non-zero pixels in XOR: {nonzero}/{total} ({100*nonzero/total:.2f}%)")
