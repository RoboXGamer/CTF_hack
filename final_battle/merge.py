from PIL import Image, ImageEnhance
import numpy as np

# Load the 3 grayscale images
a = np.array(Image.open('g_ironman.png'), dtype=np.float32)
b = np.array(Image.open('g_hidden.png'), dtype=np.float32)
c = np.array(Image.open('g_thanos.png'), dtype=np.float32)

# Simple 50% opacity merge of all 3
merged = ((a + b + c) / 3).astype(np.uint8)
Image.fromarray(merged).save('merged_all3.png')

# High contrast version
img = Image.fromarray(merged)
high = ImageEnhance.Contrast(img).enhance(5.0)
high.save('merged_all3_highcontrast.png')

# Even higher contrast
higher = ImageEnhance.Contrast(img).enhance(10.0)
higher.save('merged_all3_ultracontrast.png')

print('Done')
