from scapy.all import rdpcap, DNS, DNSQR, IP, UDP, TCP, Raw
import struct
import collections

packets = rdpcap("capture_og0oXNg.pcap")

# ── Analyze DNS packets in detail ──
# The covert channel could be in:
# 1. DNS Transaction IDs
# 2. DNS query timing
# 3. Source port variations
# 4. TTL values
# 5. IP ID field

print("=" * 60)
print("DNS COVERT CHANNEL ANALYSIS")
print("=" * 60)

dns_packets = [pkt for pkt in packets if pkt.haslayer(DNS) and pkt.haslayer(DNSQR)]
print(f"Total DNS packets: {len(dns_packets)}")

# Extract transaction IDs
txn_ids = []
src_ports = []
ip_ids = []
ttls = []
timestamps = []

for pkt in dns_packets:
    txn_ids.append(pkt[DNS].id)
    if pkt.haslayer(UDP):
        src_ports.append(pkt[UDP].sport)
    if pkt.haslayer(IP):
        ip_ids.append(pkt[IP].id)
        ttls.append(pkt[IP].ttl)
    timestamps.append(float(pkt.time))

print(f"\n--- Transaction IDs (first 50) ---")
print(txn_ids[:50])
print(f"Unique txn IDs: {len(set(txn_ids))}")
print(f"Min: {min(txn_ids)}, Max: {max(txn_ids)}")

print(f"\n--- Source Ports (first 50) ---")
print(src_ports[:50])
print(f"Unique src ports: {len(set(src_ports))}")

print(f"\n--- IP IDs (first 50) ---")
print(ip_ids[:50])
print(f"Unique IP IDs: {len(set(ip_ids))}")

print(f"\n--- TTLs (first 50) ---")  
print(ttls[:50])
print(f"Unique TTLs: {len(set(ttls))}")

# Try extracting data from transaction IDs
print("\n\n--- Attempting to decode TXN IDs as bytes ---")
txn_bytes = b''
for tid in txn_ids:
    txn_bytes += struct.pack('>H', tid)
print(f"First 200 bytes hex: {txn_bytes[:200].hex()}")
try:
    # Check for printable ASCII
    import re
    ascii_strings = re.findall(rb'[\x20-\x7e]{4,}', txn_bytes)
    print(f"ASCII strings found in TXN IDs: {ascii_strings[:20]}")
except:
    pass

# Try extracting 1 byte per TXN ID (low byte)
low_bytes = bytes([tid & 0xFF for tid in txn_ids])
print(f"\nLow bytes of TXN IDs (first 100): {low_bytes[:100].hex()}")
ascii_strings = re.findall(rb'[\x20-\x7e]{4,}', low_bytes)
print(f"ASCII in low bytes: {ascii_strings[:20]}")

# Try high byte
high_bytes = bytes([tid >> 8 for tid in txn_ids])
print(f"\nHigh bytes of TXN IDs (first 100): {high_bytes[:100].hex()}")
ascii_strings = re.findall(rb'[\x20-\x7e]{4,}', high_bytes)
print(f"ASCII in high bytes: {ascii_strings[:20]}")

# ── Analyze the payload.bin from HTTP ──
print("\n\n" + "=" * 60)
print("PAYLOAD.BIN ANALYSIS")
print("=" * 60)

# Extract the payload from TCP
for pkt in packets:
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        raw = pkt[Raw].load
        if b'200 OK' in raw:
            # Extract body after \r\n\r\n
            idx = raw.find(b'\r\n\r\n')
            if idx >= 0:
                body = raw[idx+4:]
                print(f"Payload body ({len(body)} bytes): {body.hex()}")
                print(f"ASCII attempt: {body}")
                
                # Could be an encryption key
                print(f"\nPayload could be an AES key or encrypted data")
                print(f"Length: {len(body)} bytes = {len(body)*8} bits")

# ── Check if DNS TXN IDs are actually offsets into the memory dump ──
print("\n\n" + "=" * 60)
print("DNS TXN IDs AS MEMORY OFFSETS")
print("=" * 60)

with open("memory_IcOZWTs.dmp", "rb") as f:
    mem_data = f.read()

# Try using each TXN ID as an offset (scaled)
# Memory is 2MB = 2097152 bytes, TXN IDs are 16-bit (0-65535)
# Scale factor: 2097152 / 65536 = 32
print("Using TXN IDs * 32 as memory offsets, extracting 1 byte each:")
extracted = bytearray()
for tid in txn_ids[:100]:
    offset = tid * 32
    if offset < len(mem_data):
        extracted.append(mem_data[offset])
print(f"Extracted (hex): {extracted[:50].hex()}")
print(f"Extracted (ascii): {extracted[:50]}")

# Try using TXN IDs directly as offsets 
print("\nUsing TXN IDs directly as memory offsets:")
extracted2 = bytearray()
for tid in txn_ids[:100]:
    if tid < len(mem_data):
        extracted2.append(mem_data[tid])
print(f"Extracted (hex): {extracted2[:50].hex()}")
ascii_strings = re.findall(rb'[\x20-\x7e]{4,}', bytes(extracted2))
print(f"ASCII strings: {ascii_strings[:10]}")

# ── Deeper: look at timing differences ──
print("\n\n" + "=" * 60)
print("TIMING ANALYSIS")
print("=" * 60)
if len(timestamps) > 1:
    deltas = [timestamps[i+1] - timestamps[i] for i in range(min(100, len(timestamps)-1))]
    print(f"Time deltas (first 50): {[round(d, 6) for d in deltas[:50]]}")
    print(f"Min delta: {min(deltas):.6f}, Max delta: {max(deltas):.6f}")
    
    # Check if timing encodes binary (e.g., short=0, long=1)
    avg_delta = sum(deltas) / len(deltas)
    print(f"Average delta: {avg_delta:.6f}")
    bits = ''.join('1' if d > avg_delta else '0' for d in deltas)
    print(f"Timing bits (first 100): {bits[:100]}")

# ── Check DNS query names for subtle differences ──
print("\n\n" + "=" * 60)
print("DNS QUERY NAME ANALYSIS") 
print("=" * 60)
qnames = []
for pkt in dns_packets:
    qname = pkt[DNSQR].qname
    if isinstance(qname, bytes):
        qname = qname.decode('utf-8', errors='replace')
    qnames.append(qname)

unique_qnames = set(qnames)
print(f"Unique query names: {unique_qnames}")

# Check raw bytes of DNS queries for subtle differences
print("\n--- Raw DNS layer comparison (first 5 packets) ---")
for i, pkt in enumerate(dns_packets[:5]):
    dns_raw = bytes(pkt[DNS])
    print(f"Pkt {i}: {dns_raw.hex()}")

# ── Check IP ID field for covert data ──
print("\n\n" + "=" * 60)
print("IP ID FIELD ANALYSIS")
print("=" * 60)
print(f"IP IDs (first 100): {ip_ids[:100]}")

# Try concatenating IP IDs as bytes
ipid_bytes = b''
for ipid in ip_ids:
    ipid_bytes += struct.pack('>H', ipid)
ascii_strings = re.findall(rb'[\x20-\x7e]{4,}', ipid_bytes)
print(f"ASCII in IP IDs: {ascii_strings[:20]}")

# Low bytes of IP IDs
ipid_low = bytes([ipid & 0xFF for ipid in ip_ids])
ascii_strings = re.findall(rb'[\x20-\x7e]{4,}', ipid_low)
print(f"ASCII in IP ID low bytes: {ascii_strings[:20]}")

# ── XOR payload with TXN IDs or similar ──
print("\n\n" + "=" * 60)
print("XOR ATTEMPTS")
print("=" * 60)

# The HTTP payload is 64 bytes, maybe it's a key to XOR with memory
for pkt in packets:
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        raw = pkt[Raw].load
        if b'200 OK' in raw:
            idx = raw.find(b'\r\n\r\n')
            if idx >= 0:
                key = raw[idx+4:]
                print(f"HTTP payload key ({len(key)} bytes)")
                
                # Try XOR-ing with areas around the decoy flag in memory
                decoy_pos = 1688900
                for start in [decoy_pos - 200, decoy_pos - 100, decoy_pos, decoy_pos + 50]:
                    chunk = mem_data[start:start+len(key)]
                    xored = bytes(a ^ b for a, b in zip(chunk, key))
                    ascii_s = re.findall(rb'[\x20-\x7e]{4,}', xored)
                    if ascii_s:
                        print(f"  XOR at offset {start}: {ascii_s}")
                    print(f"  XOR at offset {start}: {xored[:64]}")

# Try XOR DNS txn ID bytes with memory
print("\n--- XOR txn_bytes with nearby memory ---")
for offset in range(0, min(len(mem_data), len(txn_bytes)), len(txn_bytes)):
    chunk = mem_data[offset:offset+len(txn_bytes)]
    if len(chunk) < len(txn_bytes):
        break
    xored = bytes(a ^ b for a, b in zip(chunk, txn_bytes))
    ascii_s = re.findall(rb'[\x20-\x7e]{8,}', xored)
    if ascii_s:
        print(f"  Match at mem offset {offset:#x}: {ascii_s[:5]}")
