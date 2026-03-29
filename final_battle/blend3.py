from PIL import Image
import numpy as np

# Load all 3 images as grayscale normalized
img1 = np.array(Image.open('ironman.png').convert('L'), dtype=np.float32)
img2 = np.array(Image.open('hidden_image.png').convert('L'), dtype=np.float32)
img3 = np.array(Image.open('thanos.png').convert('L'), dtype=np.float32)

# Normalize each to 0-255
img1 = (img1 - img1.min()) / (img1.max() - img1.min()) * 255
img2 = (img2 - img2.min()) / (img2.max() - img2.min()) * 255
img3 = (img3 - img3.min()) / (img3.max() - img3.min()) * 255

# Save individual grayscales
Image.fromarray(img1.astype(np.uint8)).save('g_ironman.png')
Image.fromarray(img2.astype(np.uint8)).save('g_hidden.png')
Image.fromarray(img3.astype(np.uint8)).save('g_thanos.png')

# Simple equal blend of all 3
blend_equal = ((img1 + img2 + img3) / 3).astype(np.uint8)
Image.fromarray(blend_equal).save('all3_equal.png')

# Various weight combos for all 3
combos = [
    (0.5, 0.25, 0.25, 'iron50_hid25_than25'),
    (0.25, 0.5, 0.25, 'iron25_hid50_than25'),
    (0.25, 0.25, 0.5, 'iron25_hid25_than50'),
    (0.6, 0.2, 0.2, 'iron60_hid20_than20'),
    (0.2, 0.6, 0.2, 'iron20_hid60_than20'),
    (0.2, 0.2, 0.6, 'iron20_hid20_than60'),
    (0.7, 0.15, 0.15, 'iron70'),
    (0.15, 0.7, 0.15, 'hid70'),
    (0.15, 0.15, 0.7, 'than70'),
    (0.8, 0.1, 0.1, 'iron80'),
    (0.1, 0.8, 0.1, 'hid80'),
    (0.1, 0.1, 0.8, 'than80'),
]

for w1, w2, w3, name in combos:
    blend = (img1 * w1 + img2 * w2 + img3 * w3).astype(np.uint8)
    Image.fromarray(blend).save(f'all3_{name}.png')

# Also do inverted versions of the equal blend
inv = 255 - blend_equal
Image.fromarray(inv).save('all3_equal_inv.png')

# XOR all 3
xor = np.bitwise_xor(np.bitwise_xor(img1.astype(np.uint8), img2.astype(np.uint8)), img3.astype(np.uint8))
Image.fromarray(xor).save('all3_xor.png')
Image.fromarray(255 - xor).save('all3_xor_inv.png')

print('Done! All 3-image blends saved.')
