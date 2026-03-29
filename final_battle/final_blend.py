from PIL import Image
import numpy as np

# Load all 3 proper images
img_iron = Image.open('ironman.png').convert('RGB')
img_hidden = Image.open('hidden_image.png').convert('RGB')
img_thanos = Image.open('thanos.png').convert('RGB')

print(f"Iron Man: {img_iron.size}")
print(f"Hidden: {img_hidden.size}")
print(f"Thanos: {img_thanos.size}")

arr_iron = np.array(img_iron)
arr_hidden = np.array(img_hidden)
arr_thanos = np.array(img_thanos)

# XOR all three
xor_all = np.bitwise_xor(np.bitwise_xor(arr_iron, arr_hidden), arr_thanos)
Image.fromarray(xor_all).save('FINAL_xor_all3.png')
print("Saved FINAL_xor_all3.png")

# All pairwise XORs
Image.fromarray(np.bitwise_xor(arr_iron, arr_thanos)).save('FINAL_xor_iron_thanos.png')
Image.fromarray(np.bitwise_xor(arr_hidden, arr_thanos)).save('FINAL_xor_hidden_thanos.png')
Image.fromarray(np.bitwise_xor(arr_iron, arr_hidden)).save('FINAL_xor_iron_hidden.png')
print("Saved pairwise XORs")

# Grayscale versions
g_iron = np.array(img_iron.convert('L'))
g_hidden = np.array(img_hidden.convert('L'))
g_thanos = np.array(img_thanos.convert('L'))

# Normalized grayscale
g_iron_n = ((g_iron - g_iron.min()) / max(g_iron.max() - g_iron.min(), 1) * 255).astype(np.uint8)
g_hidden_n = ((g_hidden - g_hidden.min()) / max(g_hidden.max() - g_hidden.min(), 1) * 255).astype(np.uint8)
g_thanos_n = ((g_thanos - g_thanos.min()) / max(g_thanos.max() - g_thanos.min(), 1) * 255).astype(np.uint8)

# Save thanos grayscale
Image.fromarray(g_thanos_n).save('gray_thanos.png')

# Blends with all three at various opacity
for a in [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]:
    b = (g_iron_n * (1-a) + g_thanos_n * a).astype(np.uint8)
    Image.fromarray(b).save(f'blend_iron_thanos_{int(a*100)}.png')

# XOR grayscale all three
xor_g = np.bitwise_xor(np.bitwise_xor(g_iron_n, g_hidden_n), g_thanos_n)
Image.fromarray(xor_g).save('FINAL_xor_gray_all3.png')

# XOR grayscale pairwise
Image.fromarray(np.bitwise_xor(g_iron_n, g_thanos_n)).save('FINAL_xor_gray_it.png')
Image.fromarray(np.bitwise_xor(g_hidden_n, g_thanos_n)).save('FINAL_xor_gray_ht.png')

# Difference all combinations (normalized)
for n1, a1, n2, a2, label in [('iron', g_iron_n, 'thanos', g_thanos_n, 'it'),
                                 ('hidden', g_hidden_n, 'thanos', g_thanos_n, 'ht'),
                                 ('iron', g_iron_n, 'hidden', g_hidden_n, 'ih')]:
    d = np.abs(a1.astype(np.int16) - a2.astype(np.int16))
    d_n = ((d - d.min()) / max(d.max() - d.min(), 1) * 255).astype(np.uint8)
    Image.fromarray(d_n).save(f'FINAL_diff_{label}.png')

print("All final images saved!")
