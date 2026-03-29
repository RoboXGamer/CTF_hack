import cv2
import numpy as np

original_img = cv2.imread("og.jpg")
hidden_img = cv2.imread("challenge_sYaRo5y.png")

diff = cv2.absdiff(original_img, hidden_img)
revealed = diff * 255 # Amplify the difference