from PIL import Image
import numpy as np

img = Image.open('FINAL_xor_all3.png').convert('RGB')
arr = np.array(img)

# Wider crop - full width, top 50px  
crop = arr[0:50, 0:700, :]

# Per channel, inverted, scaled 8x
for ch, name in [(0,'R'), (1,'G'), (2,'B')]:
    channel = crop[:,:,ch]
    inv = 255 - channel
    scaled = Image.fromarray(inv).resize((channel.shape[1]*8, channel.shape[0]*8), Image.NEAREST)
    scaled.save(f'WIDE_{name}_inv.png')
    
    # Also enhanced contrast
    norm = ((channel.astype(np.float32) - channel.min()) / max(channel.max() - channel.min(), 1) * 255)
    inv_norm = 255 - norm.astype(np.uint8)
    Image.fromarray(inv_norm).resize((channel.shape[1]*8, channel.shape[0]*8), Image.NEAREST).save(f'WIDE_{name}_inv_norm.png')

# Grayscale inverted
gray = np.mean(crop, axis=2).astype(np.uint8)
inv_gray = 255 - gray
Image.fromarray(inv_gray).resize((gray.shape[1]*8, gray.shape[0]*8), Image.NEAREST).save('WIDE_gray_inv.png')

# Even wider - full width
crop_full = arr[0:45, 0:1280, :]
gray_full = np.mean(crop_full, axis=2).astype(np.uint8)
inv_full = 255 - gray_full
Image.fromarray(inv_full).resize((gray_full.shape[1]*4, gray_full.shape[0]*4), Image.NEAREST).save('FULLWIDTH_inv.png')

# Green channel full width  
g_full = 255 - crop_full[:,:,1]
Image.fromarray(g_full).resize((g_full.shape[1]*4, g_full.shape[0]*4), Image.NEAREST).save('FULLWIDTH_G_inv.png')

print("Wide zoom images saved!")
