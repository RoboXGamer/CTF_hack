from scapy.all import rdpcap, DNS, DNSQR, IP, UDP
import struct
import re
import collections

packets = rdpcap("capture_og0oXNg.pcap")
dns_packets = [pkt for pkt in packets if pkt.haslayer(DNS) and pkt.haslayer(DNSQR)]

# ── Focus on timing-based covert channel ──
timestamps = [float(pkt.time) for pkt in dns_packets]
deltas = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

print(f"Total DNS packets: {len(dns_packets)}")
print(f"Total deltas: {len(deltas)}")

# Round deltas and analyze
rounded_deltas = [round(d, 2) for d in deltas]
delta_counts = collections.Counter(rounded_deltas)
print(f"\nDelta value distribution:")
for k, v in sorted(delta_counts.items()):
    print(f"  {k}s: {v} times")

# The deltas seem to cluster around 8.09375 with some deviations
# Let's look at what values the deviations take
print(f"\nAll unique deltas: {sorted(set(rounded_deltas))}")

# The "heartbeat" is likely encoded in the timing differences
# Normal = 8.09375, variations encode data
# Let's look at the fractional part
print("\n--- Fractional analysis ---")
base = 8.09375
deviations = [(i, round(d - base, 4)) for i, d in enumerate(deltas) if abs(d - base) > 0.01]
print(f"Number of deviating packets: {len(deviations)}")
print(f"First 50 deviations: {deviations[:50]}")

# What are the deviation values?
dev_values = [d[1] for d in deviations]
dev_counts = collections.Counter([round(d, 2) for d in dev_values])
print(f"\nDeviation value counts: {dict(dev_counts)}")

# ── Maybe the deviation amount encodes a character ──
print("\n\n--- Trying: deviation as character offset ---")
# Deviation of -1 could encode some chars, -2 another, etc.
# Let's see negative deviation = offset from some base

# Alternative: the actual delta IS the value
# Deltas: 8.6, 7.84, 8.09, ... Let's check if non-8.09 deltas encode data
print("Non-standard deltas and their positions:")
non_standard = []
for i, d in enumerate(deltas):
    rd = round(d, 2)
    if rd != 8.09:
        non_standard.append((i, rd))
        
print(f"Count of non-standard: {len(non_standard)}")
print(f"First 50: {non_standard[:50]}")

# Maybe the delta value directly encodes a character
# e.g., 4.09 = 4, 5.09 = 5, etc., or the integer part
print("\n--- Trying: integer part of delta as data ---")
int_deltas = [int(d) for d in deltas]
int_counts = collections.Counter(int_deltas)
print(f"Integer delta distribution: {dict(int_counts)}")

# Extract non-8 deltas and map them
non_8_values = [int(round(d)) for _, d in non_standard]
print(f"Non-8 integer values: {non_8_values[:50]}")

# ── Try: deviations from 8 as data ──
# If base is 8, deviation = 8 - actual_integer = encoded value
print("\n--- Trying: 8 - int(delta) as encoded value ---")
encoded_values = [8 - int(round(d)) for _, d in non_standard]
print(f"Encoded values: {encoded_values[:50]}")

# ── Maybe the delta encodes nibbles or digits ──
# Integer part of delta: 4, 5, 6, 7, 8
# These could be hex nibbles or decimal digits
print("\n--- Trying: all deltas as values, concatenated ---")
all_int = [int(d) for d in deltas]
# Only non-8 values
data_stream = [v for v in all_int if v != 8]
print(f"Non-8 values only: {data_stream[:100]}")

# ── Try mapping the sub-second part ──
print("\n--- Sub-second analysis ---")
sub_seconds = [round((d % 1) * 16) for d in deltas]  # convert fractional to 0-15 range
sub_counts = collections.Counter(sub_seconds)
print(f"Sub-second * 16 distribution: {dict(sub_counts)}")

# ── Packet length analysis ──
print("\n\n" + "=" * 60)
print("PACKET LENGTH ANALYSIS")
print("=" * 60)
lengths = [len(pkt) for pkt in dns_packets]
length_counts = collections.Counter(lengths)
print(f"Packet length distribution: {dict(length_counts)}")

# ── Full raw packet analysis - look at every byte that differs ──
print("\n\n" + "=" * 60)
print("RAW PACKET BYTE DIFFERENCE ANALYSIS")
print("=" * 60)
# Compare each DNS packet raw bytes to find which bytes change
first_raw = bytes(dns_packets[1])  # skip first google.com query
print(f"Reference packet (pkt 1) hex: {first_raw.hex()}")
print(f"Reference packet length: {len(first_raw)}")

changing_positions = set()
for i in range(2, min(50, len(dns_packets))):
    pkt_raw = bytes(dns_packets[i])
    for j in range(min(len(first_raw), len(pkt_raw))):
        if first_raw[j] != pkt_raw[j]:
            changing_positions.add(j)
    if len(pkt_raw) != len(first_raw):
        print(f"  Pkt {i} has different length: {len(pkt_raw)} vs {len(first_raw)}")

print(f"\nChanging byte positions (across first 50 pkts): {sorted(changing_positions)}")

if changing_positions:
    print("\nValues at changing positions:")
    for pos in sorted(changing_positions):
        values = []
        for i in range(1, min(20, len(dns_packets))):
            pkt_raw = bytes(dns_packets[i])
            if pos < len(pkt_raw):
                values.append(pkt_raw[pos])
        print(f"  Position {pos}: {values}")

# ── Layer 2 analysis - check Ethernet src/dst ──
print("\n\n" + "=" * 60)
print("ETHERNET LAYER ANALYSIS")
print("=" * 60)
from scapy.all import Ether
for i in range(min(5, len(dns_packets))):
    pkt = dns_packets[i]
    if pkt.haslayer(Ether):
        print(f"Pkt {i}: src={pkt[Ether].src} dst={pkt[Ether].dst} type={pkt[Ether].type:#x}")
    
# ── IP layer deeper analysis ──
print("\n\n" + "=" * 60)
print("IP HEADER DEEP ANALYSIS")
print("=" * 60)
for i in range(min(10, len(dns_packets))):
    pkt = dns_packets[i]
    if pkt.haslayer(IP):
        ip = pkt[IP]
        print(f"Pkt {i}: tos={ip.tos:#x} len={ip.len} id={ip.id} flags={ip.flags} frag={ip.frag} ttl={ip.ttl} proto={ip.proto} chksum={ip.chksum:#x}")

# ── UDP checksum - sometimes used for covert channels ──
print("\n\n" + "=" * 60)
print("UDP CHECKSUMS")
print("=" * 60)
checksums = []
for pkt in dns_packets:
    if pkt.haslayer(UDP):
        checksums.append(pkt[UDP].chksum)
        
print(f"First 50 checksums: {[hex(c) for c in checksums[:50]]}")
print(f"Unique checksums: {len(set(checksums))}")

# If checksums vary, try to extract data from them
if len(set(checksums)) > 1:
    chk_bytes = b''
    for c in checksums:
        chk_bytes += struct.pack('>H', c)
    ascii_s = re.findall(rb'[\x20-\x7e]{4,}', chk_bytes)
    print(f"ASCII in checksums: {ascii_s[:20]}")
    
    chk_low = bytes([c & 0xFF for c in checksums])
    ascii_s = re.findall(rb'[\x20-\x7e]{4,}', chk_low)
    print(f"ASCII in checksum low bytes: {ascii_s[:20]}")

# ── With memory: XOR the 64-byte payload with memory at various offsets ──
print("\n\n" + "=" * 60)
print("COMPREHENSIVE XOR WITH HTTP PAYLOAD")
print("=" * 60)

with open("memory_IcOZWTs.dmp", "rb") as f:
    mem_data = f.read()

# Get the payload  
payload = bytes.fromhex("f184376b295ff909723748c7865e7e623ba4bb0bbde13f3c131faafdaff3aef6651197dc76d110067dc3d022a90af7dbf36e198543bfe7cc75c9ce329036ddba")
print(f"Payload length: {len(payload)}")

# Brute force XOR at every offset in memory looking for 'MythX' pattern
print("Searching for MythX in XOR(payload, memory[offset:offset+64])...")
for offset in range(0, len(mem_data) - 64):
    chunk = mem_data[offset:offset+64]
    xored = bytes(a ^ b for a, b in zip(chunk, payload))
    if b'MythX' in xored or b'mythx' in xored or b'MYTHX' in xored:
        print(f"  FOUND at offset {offset} ({offset:#x}): {xored}")
    # Also check for flag-like content
    if b'flag' in xored.lower():
        print(f"  'flag' at offset {offset} ({offset:#x}): {xored}")

# Also try XOR with repeating payload across entire memory
print("\nSearching for ASCII strings in XOR(payload repeating, memory)...")
key_len = len(payload)
result = bytearray(len(mem_data))
for i in range(len(mem_data)):
    result[i] = mem_data[i] ^ payload[i % key_len]
    
ascii_strings = re.findall(rb'[\x20-\x7e]{10,}', bytes(result))
print(f"Found {len(ascii_strings)} ASCII strings (len>=10)")
for s in ascii_strings[:30]:
    print(f"  {s}")

# Search specifically for MythX
mythx_pos = result.find(b'MythX')
if mythx_pos >= 0:
    print(f"\nMythX found at offset {mythx_pos}: {result[mythx_pos:mythx_pos+60]}")
