from scapy.all import rdpcap, DNS, DNSQR
import hashlib
import re

packets = rdpcap("capture_og0oXNg.pcap")
dns_packets = [pkt for pkt in packets if pkt.haslayer(DNS) and pkt.haslayer(DNSQR)]

timestamps = [float(pkt.time) for pkt in dns_packets]
deltas = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

with open("memory_IcOZWTs.dmp", "rb") as f:
    mem_data = f.read()

BASE = 259
delta_units = [round(d * 32) for d in deltas]
dev_units = [BASE - u for u in delta_units]

# IMPORTANT DISCOVERY: The cumulative drift positions read from memory
# give REPEATED characters. This means the memory has specific characters
# at specific offset ranges.
# 
# The ABSOLUTE cumulative drift points to a memory location,
# and the CHARACTER at that location is part of the message.
#
# Let me map this more carefully.

start_ts = timestamps[0]
expected = [start_ts + i * 8.09375 for i in range(len(timestamps))]
drifts_raw = [timestamps[i] - expected[i] for i in range(len(timestamps))]
drift_units = [round(d * 32) for d in drifts_raw]

# The drift goes from 0 to -105449
# Memory is 2097152 bytes
# abs(drift) goes from 0 to 105449
# 
# What if each packet reads mem_data[abs(drift)] and we only keep
# the values where the drift CHANGES?
# When drift is the same for multiple packets, that's the "base heartbeat"
# When it changes, we get a new character

print("=== CHARACTER AT EACH DRIFT CHANGE POINT ===")
prev_drift = None
message_chars = []
for i, d in enumerate(drift_units):
    if d != prev_drift:
        abs_d = abs(d)
        if abs_d < len(mem_data):
            char = mem_data[abs_d]
            message_chars.append((i, d, abs_d, chr(char) if 32 <= char < 127 else f'\\x{char:02x}'))
        prev_drift = d

print(f"Drift change points: {len(message_chars)}")
print("First 50 changes:")
for i, (idx, drift, offset, ch) in enumerate(message_chars[:50]):
    print(f"  pkt {idx}: drift={drift}, offset={offset}, char='{ch}'")

# Assemble the characters from drift change points
chars_only = [mem_data[abs(d)] for _, d, _, _ in message_chars]
assembled = bytes(chars_only)
print(f"\nAssembled string: {assembled}")
print(f"ASCII: {''.join(chr(b) if 32 <= b < 127 else '.' for b in assembled)}")

# =============================================
# But wait - the output showed repeated chars at different drift values
# suggesting each "level" of drift points to a different character.
# The KEY character is the one at the exact drift offset!
# 
# Let me also try: just read one char per UNIQUE drift value
# =============================================
print("\n\n=== ONE CHAR PER UNIQUE DRIFT ===")
seen = set()
unique_message = []
for d in drift_units:
    if d not in seen:
        seen.add(d)
        offset = abs(d)
        if offset < len(mem_data):
            unique_message.append(mem_data[offset])

print(f"Unique drift values -> chars: {len(unique_message)}")
msg = bytes(unique_message)
print(f"Message: {msg}")
print(f"ASCII: {''.join(chr(b) if 32 <= b < 127 else '.' for b in msg)}")

# =============================================
# Let me also try the ABSOLUTE drift value directly as offset
# One character per packet, reading memory at abs(drift)
# But only for packets where the delta was non-standard
# =============================================
print("\n\n=== CHAR AT DRIFT FOR NON-STANDARD PACKETS ONLY ===")
non_std_chars = []
for i in range(len(timestamps)):
    d = drift_units[i]
    if i > 0 and dev_units[i-1] != 0:
        offset = abs(d)
        if offset < len(mem_data):
            non_std_chars.append(mem_data[offset])

msg2 = bytes(non_std_chars)
print(f"Message ({len(msg2)} chars): {''.join(chr(b) if 32 <= b < 127 else '.' for b in msg2)}")
ascii_s = re.findall(rb'[\x20-\x7e]{4,}', msg2)
print(f"ASCII strings: {ascii_s[:20]}")

# =============================================
# The key observation is that drift changes are what encode data
# When drift changes (new non-standard packet), we move to a NEW memory offset
# and read the character there
# 
# Let me look at what the CHARACTER MAP looks like in memory
# =============================================
print("\n\n=== MEMORY CHARACTER MAP ===")
# What characters are at various offsets?
for offset in range(0, 200000, 1000):
    char = mem_data[offset]
    if 32 <= char < 127:
        print(f"  offset {offset}: '{chr(char)}'", end='')
        
print()

# Actually let me check: do specific offset RANGES have the same character?
# Sample every 8192 bytes
print("\n=== Memory sampling every 100 bytes (first 5000) ===")
for offset in range(0, 5000, 100):
    chars = ''.join(chr(mem_data[offset + j]) if 32 <= mem_data[offset + j] < 127 else '.' for j in range(min(10, len(mem_data) - offset)))
    print(f"  {offset:6d}: {chars}")

# =============================================ov
# Let me check if the memory has a pattern where specific offsets 
# all contain the same printable character - like a lookup table
# =============================================
print("\n\n=== CHARACTER AT ABSOLUTE OFFSETS 0-256 ===")
for i in range(256):
    ch = mem_data[i]
    if 32 <= ch < 127:
        print(f"  mem[{i}] = {ch} '{chr(ch)}'")

# =============================================
# Think differently: 
# The drift accumulates as we observe non-standard deltas
# Each non-standard delta "moves" the pointer in memory
# The character at the NEW position is part of the flag
#
# But the drift goes to -105449 and the chars at those offsets repeat
# That means the memory has IDENTICAL bytes at nearby offsets
# which lines up with the near-maximum entropy (encrypted)
#
# Unless... those characters ARE the flag characters, scattered in memory
# at positions that correspond to specific drift values!
# =============================================

# Let me check: at the absolute drift values, are there meaningful chars?
print("\n\n=== CHARACTERS AT ALL ABSOLUTE DRIFT VALUES ===")
all_abs_drifts = sorted(set(abs(d) for d in drift_units))
print(f"Unique absolute drift values: {len(all_abs_drifts)}")
print(f"Range: {min(all_abs_drifts)} to {max(all_abs_drifts)}")

# Read the character at each unique absolute drift
drift_chars = []
for d in all_abs_drifts:
    if d < len(mem_data):
        ch = mem_data[d]
        drift_chars.append((d, ch))
        if 32 <= ch < 127 and len(drift_chars) <= 100:
            pass  # will print below

# Show all printable ones
printable_drift_chars = [(d, ch) for d, ch in drift_chars if 32 <= ch < 127]
print(f"Printable chars at drift offsets: {len(printable_drift_chars)}")
print("Characters:")
msg = ''.join(chr(ch) for _, ch in printable_drift_chars)
print(f"  {msg}")

# In ORDER of first appearance (by drift sequence, not sorted)
print("\n=== CHARS IN ORDER OF APPEARANCE ===")
seen = set()
ordered_chars = []
for d in drift_units:
    ad = abs(d)
    if ad not in seen and ad < len(mem_data):
        seen.add(ad)
        ch = mem_data[ad]
        ordered_chars.append(chr(ch) if 32 <= ch < 127 else '.')
print(''.join(ordered_chars))

# Also try: reading memory at position = the deviation (not drift)
# Each non-zero deviation value as a direct memory offset
print("\n\n=== DEVIATION DIRECT TO MEMORY ===")
dev_chars = []
for d in dev_units:
    if d != 0 and 0 < d < len(mem_data):
        dev_chars.append(mem_data[d])
msg = bytes(dev_chars)
print(f"Message: {''.join(chr(b) if 32 <= b < 127 else '.' for b in msg[:100])}")
