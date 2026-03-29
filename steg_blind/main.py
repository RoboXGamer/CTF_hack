import cv2
import numpy as np

def reveal_flag(image_path):
    # Load the image
    img = cv2.imread(image_path)
    if img is None:
        print("Image not found.")
        return

    # Method 1: Bitwise Extraction (LSB)
    # This isolates the last bit of the Blue channel and scales it to 255 (white)
    lsb_reveal = (img[:, :, 0] & 1) * 255
    cv2.imwrite('revealed_lsb.png', lsb_reveal)

    # Method 2: Contrast Stretching / Thresholding
    # This amplifies any tiny variations in the image
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    # We apply a very sensitive threshold to catch 1-unit differences
    _, thresh_reveal = cv2.threshold(gray, gray.min(), 255, cv2.THRESH_BINARY_INV)
    cv2.imwrite('revealed_contrast.png', thresh_reveal)

    print("Reveal complete. Check 'revealed_lsb.png' and 'revealed_contrast.png'.")

# Usage
reveal_flag('challenge_sYaRo5y.png')
