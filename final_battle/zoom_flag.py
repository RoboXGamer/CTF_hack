from PIL import Image, ImageEnhance, ImageOps
import numpy as np

# Load the three-way XOR
img = Image.open('FINAL_xor_all3.png').convert('RGB')
arr = np.array(img)

# Crop top-left corner where text is visible
crop = arr[0:60, 0:350, :]
crop_img = Image.fromarray(crop)

# Scale up 6x
scaled = crop_img.resize((crop.shape[1]*6, crop.shape[0]*6), Image.NEAREST)
scaled.save('ZOOM_raw.png')

# Grayscale version
gray = np.mean(crop, axis=2)

# Inverted threshold (text appears darker)
for t in [80, 100, 120, 140, 160, 180, 200]:
    binary = ((gray < t) * 255).astype(np.uint8)
    img_b = Image.fromarray(binary)
    img_b.resize((binary.shape[1]*6, binary.shape[0]*6), Image.NEAREST).save(f'ZOOM_dark_t{t}.png')

# Regular threshold (text appears lighter)
for t in [80, 100, 120, 140, 160]:
    binary = ((gray > t) * 255).astype(np.uint8)
    img_b = Image.fromarray(binary)
    img_b.resize((binary.shape[1]*6, binary.shape[0]*6), Image.NEAREST).save(f'ZOOM_light_t{t}.png')

# Per channel
for ch, name in [(0,'R'), (1,'G'), (2,'B')]:
    channel = crop[:,:,ch]
    # Scale up  
    scaled_ch = Image.fromarray(channel).resize((channel.shape[1]*6, channel.shape[0]*6), Image.NEAREST)
    scaled_ch.save(f'ZOOM_{name}.png')
    
    # Inverted
    inv = 255 - channel
    Image.fromarray(inv).resize((inv.shape[1]*6, inv.shape[0]*6), Image.NEAREST).save(f'ZOOM_{name}_inv.png')

# High contrast
contrast = ImageEnhance.Contrast(scaled)
contrast.enhance(5.0).save('ZOOM_contrast.png')

print("Zoom images saved!")
