import struct

with open('challenge_DYSuBRF.png', 'rb') as f:
    sig = f.read(8)
    print('PNG Signature:', sig.hex())
    
    while True:
        header = f.read(8)
        if len(header) < 8:
            break
        length = struct.unpack('>I', header[:4])[0]
        chunk_type = header[4:8].decode('ascii', errors='replace')
        data = f.read(length)
        crc = f.read(4)
        
        standard = ('IHDR','PLTE','IDAT','IEND','tEXt','iTXt','zTXt',
                     'sRGB','gAMA','cHRM','pHYs','bKGD','tIME','iCCP',
                     'sBIT','sPLT','hIST','tRNS')
        
        if chunk_type == 'IDAT':
            print(f'Chunk: {chunk_type}, Length: {length}')
        else:
            print(f'Chunk: {chunk_type}, Length: {length}')
            if chunk_type not in standard:
                print(f'  *** UNKNOWN/CUSTOM CHUNK ***')
                print(f'  Hex: {data.hex()}')
                try:
                    print(f'  Text: {data.decode("utf-8", errors="replace")}')
                except:
                    pass
            elif chunk_type in ('tEXt', 'iTXt', 'zTXt'):
                try:
                    print(f'  Text: {data.decode("utf-8", errors="replace")}')
                except:
                    print(f'  Hex: {data.hex()}')

    # Also check for data after IEND
    remaining = f.read()
    if remaining:
        print(f'\n--- DATA AFTER IEND ({len(remaining)} bytes) ---')
        print(f'Hex: {remaining.hex()}')
        try:
            print(f'Text: {remaining.decode("utf-8", errors="replace")}')
        except:
            pass
