from PIL import Image
import numpy as np
import struct

print("=== Checking AVIF for hidden data ===")
f = open('snap_layer1.avif', 'rb')
avif_data = f.read()
f.close()
print(f"AVIF size: {len(avif_data)}")

# Search for embedded files in AVIF
for sig_name, sig in [('PNG', b'\x89PNG\r\n\x1a\n'), ('JPEG', b'\xff\xd8\xff'), 
                       ('ZIP', b'PK\x03\x04'), ('AVIF/ftyp', b'ftyp'),
                       ('RIFF', b'RIFF'), ('GIF', b'GIF8')]:
    positions = [i for i in range(len(avif_data)) if avif_data[i:i+len(sig)] == sig]
    if positions:
        print(f"  {sig_name} at: {positions}")

# Search for text keywords
for kw in [b'thanos', b'Thanos', b'titan', b'Titan', b'mythx', b'flag', b'hidden', b'secret', b'password']:
    pos = avif_data.find(kw)
    if pos >= 0:
        print(f"  '{kw.decode()}' at offset {pos}: {avif_data[max(0,pos-10):pos+40]}")

print("\n=== Checking hidden_image.png for MORE hidden data ===")
f = open('hidden_image.png', 'rb')
hidden_data = f.read()
f.close()

# Parse all chunks in hidden_image.png
pos = 8
while pos < len(hidden_data):
    length = struct.unpack('>I', hidden_data[pos:pos+4])[0]
    chunk_type = hidden_data[pos+4:pos+8].decode('ascii', errors='replace')
    chunk_data = hidden_data[pos+8:pos+8+length]
    
    if chunk_type in ('tEXt', 'iTXt', 'zTXt'):
        null_pos = chunk_data.find(b'\x00')
        kw = chunk_data[:null_pos].decode(errors='replace') if null_pos >= 0 else '?'
        print(f"  TEXT chunk '{chunk_type}': keyword='{kw}', size={length}")
        if length < 500:
            print(f"    Value: {chunk_data[null_pos+1:]}")
        else:
            print(f"    Value preview: {chunk_data[null_pos+1:null_pos+100]}")
    elif chunk_type not in ('IDAT', 'IEND'):
        print(f"  Chunk '{chunk_type}': size={length}")
    
    pos += 12 + length
    if chunk_type == 'IEND':
        remaining = len(hidden_data) - pos
        if remaining > 0:
            print(f"  DATA AFTER IEND: {remaining} bytes!")
            print(f"    Header: {hidden_data[pos:pos+32].hex()}")
        break

# Search for embedded files in hidden_image
for sig_name, sig in [('PNG', b'\x89PNG\r\n\x1a\n'), ('JPEG', b'\xff\xd8\xff'), 
                       ('ZIP', b'PK\x03\x04')]:
    positions = [i for i in range(1, len(hidden_data)) if hidden_data[i:i+len(sig)] == sig]
    if positions:
        print(f"  {sig_name} embedded at: {positions}")

# Search for text in hidden_image
for kw in [b'thanos', b'Thanos', b'titan', b'Titan', b'mythx', b'password', b'secret']:
    pos = hidden_data.find(kw)
    if pos >= 0:
        print(f"  '{kw.decode()}' at {pos}: {hidden_data[max(0,pos-10):pos+40]}")

print("\n=== Checking original The_Snap.png for MORE hidden data ===")
f = open('The_Snap.png', 'rb')
snap_data = f.read()
f.close()

# The AVIF part is 0 to 184294, ZIP starts at 184294
# Check if there's data between AVIF end and ZIP start
# or if the AVIF itself has multiple images

# Search for additional ftyp boxes  
for kw in [b'thanos', b'Thanos', b'titan', b'Titan', b'mythx', b'secret', b'password', b'steg']:
    positions = []
    start = 0
    while True:
        pos = snap_data.find(kw, start)
        if pos == -1:
            break
        positions.append(pos)
        start = pos + 1
    if positions:
        print(f"  '{kw.decode()}' at: {positions}")
        for p in positions[:3]:
            print(f"    Context: {snap_data[max(0,p-10):p+50]}")

# Check AVIF for multiple image items (AVIF can contain multiple images)
# Look for 'iloc' box which lists image locations
iloc_pos = avif_data.find(b'iloc')
if iloc_pos >= 0:
    print(f"\n  AVIF iloc box at {iloc_pos}")
    print(f"    Data: {avif_data[iloc_pos:iloc_pos+64].hex()}")

# Look for 'iprp', 'ipma', 'ispe' boxes
for box in [b'iprp', b'ipma', b'ispe', b'pixi', b'auxC', b'pitm', b'iinf', b'infe']:
    pos = avif_data.find(box)
    if pos >= 0:
        print(f"  AVIF box '{box.decode()}' at {pos}")

print("\n=== Loading AVIF as image - check for alpha/multiple frames ===")
img_avif = Image.open('snap_layer1.avif')
print(f"  Mode: {img_avif.mode}")
print(f"  Size: {img_avif.size}")
print(f"  Info: {img_avif.info}")

# Check if AVIF has alpha
if 'A' in img_avif.mode:
    print("  HAS ALPHA CHANNEL!")
    alpha = np.array(img_avif.split()[-1])
    print(f"  Alpha range: {alpha.min()} - {alpha.max()}")
    Image.fromarray(alpha).save('avif_alpha.png')
    print("  Saved avif_alpha.png")

# Try to convert to RGBA
try:
    img_rgba = img_avif.convert('RGBA')
    arr_rgba = np.array(img_rgba)
    alpha = arr_rgba[:,:,3]
    print(f"  RGBA alpha range: {alpha.min()} - {alpha.max()}")
    unique_alpha = np.unique(alpha)
    print(f"  Unique alpha values: {len(unique_alpha)}")
    if len(unique_alpha) > 1 and len(unique_alpha) < 50:
        print(f"  Alpha values: {unique_alpha}")
except Exception as e:
    print(f"  RGBA convert error: {e}")

# Check for multiple frames (animated AVIF)
try:
    n_frames = getattr(img_avif, 'n_frames', 1)
    print(f"  Frames: {n_frames}")
    if n_frames > 1:
        for i in range(n_frames):
            img_avif.seek(i)
            frame = img_avif.copy()
            frame.save(f'avif_frame{i}.png')
            print(f"  Saved frame {i}")
except Exception as e:
    print(f"  Frame check: {e}")
