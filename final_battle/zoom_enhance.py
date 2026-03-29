from PIL import Image, ImageEnhance, ImageOps
import numpy as np

img1 = Image.open('ironman.png').convert('RGB')
img2 = Image.open('hidden_image.png').convert('RGB')
arr1 = np.array(img1)
arr2 = np.array(img2)
xor_12 = np.bitwise_xor(arr1, arr2)

# Very tight crop of top-left corner and scale up
# Focus on first ~50 pixels height, ~300 width
crop = xor_12[0:60, 0:350, :]

# Multiple enhancement approaches
# 1. Scale up 4x for readability
crop_img = Image.fromarray(crop)
scaled = crop_img.resize((crop.shape[1]*4, crop.shape[0]*4), Image.NEAREST)
scaled.save('zoom_topleft_raw.png')

# 2. Grayscale threshold
gray = np.mean(crop, axis=2)
for t in [30, 40, 50, 60, 80, 100, 128, 150]:
    binary = ((gray > t) * 255).astype(np.uint8)
    img_bin = Image.fromarray(binary)
    img_bin_scaled = img_bin.resize((binary.shape[1]*4, binary.shape[0]*4), Image.NEAREST)
    img_bin_scaled.save(f'zoom_thresh{t}.png')

# 3. Inverted threshold (text might be darker than bg)
for t in [30, 50, 80, 100, 128, 150]:
    binary_inv = ((gray < t) * 255).astype(np.uint8)
    img_inv = Image.fromarray(binary_inv)
    img_inv_scaled = img_inv.resize((binary_inv.shape[1]*4, binary_inv.shape[0]*4), Image.NEAREST)
    img_inv_scaled.save(f'zoom_inv_thresh{t}.png')

# 4. Per-channel analysis at top-left
for ch, name in [(0,'R'), (1,'G'), (2,'B')]:
    channel = crop[:,:,ch]
    for t in [50, 80, 128]:
        binary = ((channel < t) * 255).astype(np.uint8)
        img_ch = Image.fromarray(binary)
        img_ch_scaled = img_ch.resize((binary.shape[1]*4, binary.shape[0]*4), Image.NEAREST)
        img_ch_scaled.save(f'zoom_{name}_inv_t{t}.png')

print('All zoom images saved')
