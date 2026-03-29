import struct

# Analyze hidden_image.png
f = open('hidden_image.png', 'rb')
data = f.read()
f.close()

pos = 8
while pos < len(data):
    length = struct.unpack('>I', data[pos:pos+4])[0]
    chunk_type = data[pos+4:pos+8].decode('ascii', errors='replace')
    chunk_data = data[pos+8:pos+8+length]
    
    if chunk_type == 'IHDR':
        w = struct.unpack('>I', chunk_data[0:4])[0]
        h = struct.unpack('>I', chunk_data[4:8])[0]
        bd = chunk_data[8]
        ct = chunk_data[9]
        print(f'hidden_image.png: {w}x{h}, bit_depth={bd}, color_type={ct}')
    elif chunk_type in ('tEXt', 'iTXt', 'zTXt'):
        null_pos = chunk_data.index(b'\x00') if b'\x00' in chunk_data else -1
        if null_pos >= 0:
            kw = chunk_data[:null_pos].decode(errors='replace')
            val = chunk_data[null_pos+1:null_pos+200]
            print(f'  TEXT: {kw} = {val}')
    elif chunk_type == 'IEND':
        break
    
    pos += 12 + length

print()

# Also check ironman.png dimensions
f = open('ironman.png', 'rb')
data = f.read()
f.close()
pos = 8
length = struct.unpack('>I', data[pos:pos+4])[0]
chunk_data = data[pos+8:pos+8+length]
w = struct.unpack('>I', chunk_data[0:4])[0]
h = struct.unpack('>I', chunk_data[4:8])[0]
bd = chunk_data[8]
ct = chunk_data[9]
print(f'ironman.png: {w}x{h}, bit_depth={bd}, color_type={ct}')

# Check snap_layer1.avif - we need ffprobe or similar
print(f'\nsnap_layer1.avif size: {len(open("snap_layer1.avif","rb").read())} bytes')
