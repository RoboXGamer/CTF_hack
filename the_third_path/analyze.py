from scapy.all import rdpcap, DNS, DNSQR, DNSRR, IP, UDP, TCP, ICMP, Raw
import struct
import collections

# ── PCAP Analysis ──
print("=" * 60)
print("PCAP ANALYSIS")
print("=" * 60)

packets = rdpcap("capture_og0oXNg.pcap")
print(f"Total packets: {len(packets)}")

# Protocol breakdown
proto_count = collections.Counter()
for pkt in packets:
    if pkt.haslayer(TCP):
        proto_count['TCP'] += 1
    if pkt.haslayer(UDP):
        proto_count['UDP'] += 1
    if pkt.haslayer(ICMP):
        proto_count['ICMP'] += 1
    if pkt.haslayer(DNS):
        proto_count['DNS'] += 1
    if pkt.haslayer(Raw):
        proto_count['Raw'] += 1

print(f"\nProtocol breakdown: {dict(proto_count)}")

# IP addresses
src_ips = collections.Counter()
dst_ips = collections.Counter()
for pkt in packets:
    if pkt.haslayer(IP):
        src_ips[pkt[IP].src] += 1
        dst_ips[pkt[IP].dst] += 1

print(f"\nSource IPs: {dict(src_ips)}")
print(f"Dest IPs: {dict(dst_ips)}")

# DNS queries
print("\n--- DNS Queries ---")
for pkt in packets:
    if pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname.decode() if isinstance(pkt[DNSQR].qname, bytes) else pkt[DNSQR].qname
        print(f"  Query: {qname}")

# DNS answers
print("\n--- DNS Answers ---")
for pkt in packets:
    if pkt.haslayer(DNSRR):
        for i in range(pkt[DNS].ancount):
            rr = pkt[DNS].an[i] if pkt[DNS].ancount > 1 else pkt[DNS].an
            rrname = rr.rrname.decode() if isinstance(rr.rrname, bytes) else rr.rrname
            rdata = rr.rdata
            if isinstance(rdata, bytes):
                rdata = rdata.decode('utf-8', errors='replace')
            print(f"  Answer: {rrname} -> {rdata} (type={rr.type})")
            break

# TCP streams: check ports
print("\n--- TCP Connections ---")
tcp_conns = set()
for pkt in packets:
    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        conn = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
        tcp_conns.add(conn)
for c in sorted(tcp_conns):
    print(f"  {c[0]}:{c[1]} -> {c[2]}:{c[3]}")

# UDP streams: check ports
print("\n--- UDP Connections ---")
udp_conns = set()
for pkt in packets:
    if pkt.haslayer(UDP) and pkt.haslayer(IP):
        conn = (pkt[IP].src, pkt[UDP].sport, pkt[IP].dst, pkt[UDP].dport)
        udp_conns.add(conn)
for c in sorted(udp_conns):
    print(f"  {c[0]}:{c[1]} -> {c[2]}:{c[3]}")

# ICMP analysis
print("\n--- ICMP Packets ---")
icmp_count = 0
for pkt in packets:
    if pkt.haslayer(ICMP):
        icmp_count += 1
        if icmp_count <= 10:
            icmp_layer = pkt[ICMP]
            print(f"  Type={icmp_layer.type} Code={icmp_layer.code} ID={icmp_layer.id} Seq={icmp_layer.seq}")
            if pkt.haslayer(Raw):
                raw = pkt[Raw].load
                print(f"    Raw payload ({len(raw)}b): {raw[:50].hex()}")
                try:
                    print(f"    ASCII: {raw[:50].decode('ascii', errors='replace')}")
                except:
                    pass
print(f"  Total ICMP packets: {icmp_count}")

# Look for any raw data in TCP/UDP
print("\n--- Sample Raw Payloads (first 20) ---")
count = 0
for pkt in packets:
    if pkt.haslayer(Raw) and not pkt.haslayer(DNS):
        raw = pkt[Raw].load
        proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "ICMP" if pkt.haslayer(ICMP) else "Other"
        sport = pkt[TCP].sport if pkt.haslayer(TCP) else pkt[UDP].sport if pkt.haslayer(UDP) else 0
        dport = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport if pkt.haslayer(UDP) else 0
        print(f"  [{proto} {sport}->{dport}] len={len(raw)}: {raw[:80].hex()}")
        try:
            print(f"    ASCII: {raw[:80]}")
        except:
            pass
        count += 1
        if count >= 20:
            break

# ── Memory Dump Analysis ──
print("\n" + "=" * 60)
print("MEMORY DUMP ANALYSIS")
print("=" * 60)

with open("memory_IcOZWTs.dmp", "rb") as f:
    mem_data = f.read()

print(f"Memory dump size: {len(mem_data)} bytes")

# Search for strings
print("\n--- Interesting Strings in Memory Dump ---")
import re
strings = re.findall(rb'[\x20-\x7e]{6,}', mem_data)
print(f"Total printable strings (len>=6): {len(strings)}")
for s in strings[:50]:
    print(f"  {s.decode('ascii')}")

# Look for known patterns
print("\n--- Searching for key patterns ---")
for pattern in [b'MythX', b'flag', b'FLAG', b'key', b'KEY', b'secret', b'SECRET', b'password', b'AES', b'RSA', b'BEGIN', b'covert', b'heartbeat']:
    positions = [m.start() for m in re.finditer(re.escape(pattern), mem_data)]
    if positions:
        print(f"  Found '{pattern.decode()}' at positions: {positions[:10]}")
        for pos in positions[:3]:
            context = mem_data[max(0,pos-20):pos+len(pattern)+40]
            print(f"    Context: {context}")

# Entropy analysis of memory dump sections
print("\n--- Memory dump section entropy ---")
import math
def entropy(data):
    if not data:
        return 0
    freq = collections.Counter(data)
    length = len(data)
    return -sum((c/length) * math.log2(c/length) for c in freq.values())

chunk_size = len(mem_data) // 16
for i in range(16):
    chunk = mem_data[i*chunk_size:(i+1)*chunk_size]
    ent = entropy(chunk)
    print(f"  Chunk {i}: offset {i*chunk_size:#x}, entropy={ent:.4f}")
