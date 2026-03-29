from PIL import Image, ImageChops
import numpy as np

img1 = Image.open('ironman.png').convert('L')  # grayscale
img2 = Image.open('hidden_image.png').convert('L')  # grayscale

# Normalize both to 0-255 range
arr1 = np.array(img1, dtype=np.float32)
arr2 = np.array(img2, dtype=np.float32)
arr1 = ((arr1 - arr1.min()) / (arr1.max() - arr1.min()) * 255).astype(np.uint8)
arr2 = ((arr2 - arr2.min()) / (arr2.max() - arr2.min()) * 255).astype(np.uint8)

# Save normalized originals
Image.fromarray(arr1).save('gray_ironman.png')
Image.fromarray(arr2).save('gray_hidden.png')

# Blend at various opacities
for alpha in [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]:
    blended = (arr1.astype(np.float32) * (1 - alpha) + arr2.astype(np.float32) * alpha).astype(np.uint8)
    Image.fromarray(blended).save(f'blend_{int(alpha*100)}.png')

# Also do difference, multiply, screen blending
diff = np.abs(arr1.astype(np.int16) - arr2.astype(np.int16)).astype(np.uint8)
Image.fromarray(diff).save('blend_diff.png')

# Difference enhanced (normalized to full range)
if diff.max() > diff.min():
    diff_norm = ((diff.astype(np.float32) - diff.min()) / (diff.max() - diff.min()) * 255).astype(np.uint8)
else:
    diff_norm = diff
Image.fromarray(diff_norm).save('blend_diff_norm.png')

# Multiply blend
mult = (arr1.astype(np.float32) / 255 * arr2.astype(np.float32) / 255 * 255).astype(np.uint8)
Image.fromarray(mult).save('blend_multiply.png')

# Screen blend
screen = (255 - ((255 - arr1.astype(np.float32)) / 255 * (255 - arr2.astype(np.float32)) / 255 * 255)).astype(np.uint8)
Image.fromarray(screen).save('blend_screen.png')

# XOR grayscale
xor_g = np.bitwise_xor(arr1, arr2)
Image.fromarray(xor_g).save('blend_xor.png')

# XOR inverted
Image.fromarray(255 - xor_g).save('blend_xor_inv.png')

# Subtract (img1 - img2, clamped)
sub = np.clip(arr1.astype(np.int16) - arr2.astype(np.int16), 0, 255).astype(np.uint8)
Image.fromarray(sub).save('blend_sub12.png')

sub2 = np.clip(arr2.astype(np.int16) - arr1.astype(np.int16), 0, 255).astype(np.uint8)
Image.fromarray(sub2).save('blend_sub21.png')

print('All blends saved!')
