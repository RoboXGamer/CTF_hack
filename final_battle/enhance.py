from PIL import Image, ImageEnhance, ImageFilter, ImageOps
import numpy as np

img1 = Image.open('ironman.png').convert('RGB')
img2 = Image.open('hidden_image.png').convert('RGB')

arr1 = np.array(img1)
arr2 = np.array(img2)

# XOR the two images
xor_12 = np.bitwise_xor(arr1, arr2)
xor_img = Image.fromarray(xor_12)

# Crop the top-left corner (try various sizes)
for size_name, box in [('small', (0, 0, 400, 100)), ('medium', (0, 0, 600, 150)), ('large', (0, 0, 800, 200)), ('xlarge', (0, 0, 1000, 300))]:
    crop = xor_img.crop(box)
    crop.save(f'topleft_{size_name}.png')
    
    # Enhance contrast heavily
    enhancer = ImageEnhance.Contrast(crop)
    enhanced = enhancer.enhance(10.0)
    enhanced.save(f'topleft_{size_name}_contrast.png')
    
    # Invert
    inverted = ImageOps.invert(crop)
    inverted.save(f'topleft_{size_name}_inverted.png')
    
    # Grayscale + threshold
    gray = crop.convert('L')
    # Multiple thresholds
    for thresh in [10, 20, 30, 50, 80, 128]:
        binary = gray.point(lambda x: 255 if x > thresh else 0)
        binary.save(f'topleft_{size_name}_thresh{thresh}.png')
    
    # Enhance brightness
    bright = ImageEnhance.Brightness(crop)
    b = bright.enhance(5.0)
    b.save(f'topleft_{size_name}_bright.png')

# Also try: multiply XOR values to amplify differences
xor_amplified = np.clip(xor_12.astype(np.float32) * 20, 0, 255).astype(np.uint8)
amp_img = Image.fromarray(xor_amplified)
amp_crop = amp_img.crop((0, 0, 800, 200))
amp_crop.save('topleft_amplified.png')

# Try per-channel enhancement in top-left
crop_arr = xor_12[0:200, 0:800, :]
for ch, name in [(0, 'red'), (1, 'green'), (2, 'blue')]:
    channel = crop_arr[:, :, ch]
    # Normalize to full range
    if channel.max() > channel.min():
        normalized = ((channel.astype(np.float32) - channel.min()) / (channel.max() - channel.min()) * 255).astype(np.uint8)
    else:
        normalized = channel
    Image.fromarray(normalized).save(f'topleft_{name}_normalized.png')
    
    # Threshold
    binary = (channel > 5).astype(np.uint8) * 255
    Image.fromarray(binary).save(f'topleft_{name}_binary.png')

# Also try: only look at the difference (not XOR) - absolute difference
diff = np.abs(arr1.astype(np.int16) - arr2.astype(np.int16))
diff_crop = diff[0:200, 0:800, :]
diff_amplified = np.clip(diff_crop * 20, 0, 255).astype(np.uint8)
Image.fromarray(diff_amplified).save('topleft_diff_amplified.png')

# Try enhancing just the low values (where differences are subtle)
# Invert XOR so dark areas become bright
inverted_arr = 255 - xor_12
inv_enhanced = np.clip(inverted_arr.astype(np.float32) * 5, 0, 255).astype(np.uint8)
inv_crop = inv_enhanced[0:200, 0:800, :]
Image.fromarray(inv_crop).save('topleft_inv_enhanced.png')

print("All enhanced images saved!")
print("Check topleft_*_thresh*.png and topleft_amplified.png for the flag text")
