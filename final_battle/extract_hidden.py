import struct
import base64

f = open('ironman.png', 'rb')
data = f.read()
f.close()

pos = 2654
length = struct.unpack('>I', data[pos:pos+4])[0]
chunk_data = data[pos+8:pos+8+length]

null_pos = chunk_data.index(b'\x00')
keyword = chunk_data[:null_pos].decode()
text_data = chunk_data[null_pos+1:]

print('Keyword:', keyword)
print('Text length:', len(text_data))
print('First 300 chars:', text_data[:300])

# The data looks like it starts with "eNoAQkC9v4lQTkcNChoK..." which is base64
# Let's try base64 decode
try:
    decoded = base64.b64decode(text_data)
    print('\nDecoded size:', len(decoded))
    print('Decoded header hex:', decoded[:32].hex())
    is_png = decoded[:8] == b'\x89PNG\r\n\x1a\n'
    print('Is PNG:', is_png)
    
    if is_png:
        with open('hidden_image.png', 'wb') as out:
            out.write(decoded)
        print('Saved as hidden_image.png')
    else:
        # Maybe it's zlib compressed base64
        import zlib
        try:
            decompressed = zlib.decompress(decoded)
            print('Decompressed size:', len(decompressed))
            print('Decompressed header:', decompressed[:32].hex())
            is_png2 = decompressed[:8] == b'\x89PNG\r\n\x1a\n'
            print('Decompressed is PNG:', is_png2)
            with open('hidden_image.png', 'wb') as out:
                out.write(decompressed)
            print('Saved decompressed as hidden_image.png')
        except Exception as e:
            print('Zlib decompress error:', e)
            with open('hidden_raw.bin', 'wb') as out:
                out.write(decoded)
            print('Saved raw decoded as hidden_raw.bin')
except Exception as e:
    print('Base64 decode error:', e)
    # Try removing non-base64 chars
    import re
    cleaned = re.sub(rb'[^A-Za-z0-9+/=]', b'', text_data)
    print('Cleaned length:', len(cleaned))
    try:
        decoded = base64.b64decode(cleaned)
        print('Decoded size:', len(decoded))
        print('Decoded header:', decoded[:32].hex())
        with open('hidden_raw.bin', 'wb') as out:
            out.write(decoded)
        print('Saved as hidden_raw.bin')
    except Exception as e2:
        print('Still failed:', e2)
