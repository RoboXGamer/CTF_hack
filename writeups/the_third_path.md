# CTF Writeup: The Third Path

**Challenge Name:** The Third Path  
**Category:** Forensics / Network Security  
**Flag Format:** `MythX{...}`

### Challenge Description

We've captured a complete snapshot of a compromised analyst workstation, including a memory dump and the corresponding network traffic. Initial triage teams found ransomware artifacts and encrypted exfiltration streams, but none of the decrypted data makes sense.

We believe they missed a highly advanced covert channel. Can you identify the subtle heartbeat bridging the network and RAM, bypassing the decoys to find the truth?

---

### Solution

#### Step 1: Memory & Network Triage

We were provided with a memory dump (`memory_IcOZWTs.dmp`) and a PCAP file (`capture_og0oXNg.pcap`).

- **Memory Strings:** A string search in the memory dump revealed a decoy flag: `MythX{m3m0ry_r4ns0mw4r3_d3c0y}`.
- **Encrypted Hint:** We also found references to a password: `Password is Rabb1tH0le123!` and a path to `payload.bin`.
- **Network Activity:** The PCAP showed an HTTP download of `payload.bin` from `evil.com` and 3,002 suspicious DNS queries directed at `update.windows.com`.

---

### Step 2: Bypassing the Decoys

Using the discovered password, we decrypted the `payload.bin` file using AES-CBC.

**Result:** The file decrypted to another decoy: `MythX{nice_try_but_keep_looking}`. This confirmed the challenge description's warning about "bypassing the decoys."

---

### Step 3: Finding the Hidden Info

A deep binary scan of the 2MB memory dump revealed an embedded PNG image at offset `925702`. Upon extraction, the image served as a technical hint:

| Feature        | Info                                                   |
| :------------- | :----------------------------------------------------- |
| **Message**    | Missing Data Info: 600x40 1-bit monochrome (8 aligned) |
| **Total Size** | (600/8) \* 40 = 3,000 bytes                            |

This indicated we needed to find exactly 3,000 bytes of data from a secondary source to reconstruct an image.

---

### Step 4: Timing Analysis ("The Heartbeat")

The "subtle heartbeat bridging the network and RAM" pointed to the DNS traffic. While the DNS packet payloads were identical, the **timing intervals (deltas)** between the 3,002 packets were not.

We analyzed the packet timestamps using Python:

1.  Most deltas were exactly **8.09375 seconds**.
2.  Deviations from this base interval were observed in exactly 3,001 instances.
3.  By quantizing the timing into units of 1/32nd of a second (`delta * 32`), we found that the deviations directly encoded byte values:
    - `Base Units = 8.09375 * 32 = 259`
    - `Encoded Byte = 259 - (Packet Delta * 32)`

---

### Step 5: Reconstruction

We extracted the 3,000 bytes from the DNS timing intervals and mapped them to a 1-bit monochrome bitmap of 600x40 pixels as specified by the internal memory hint.

The resulting reconstructed image revealed the true flag written in text.

---

### Step 6: Flag

The real flag hidden in the timing covert channel was:

```text
MythX{c0v3rt_dn5_t1m1n6_n1ghtm4r3}
```

---

### Tools Used

- **Python (Scapy):** For precise PCAP timing extraction and analysis.
- **Python (PyCryptodome):** For AES decryption of the decoy payloads.
- **Python (Pillow/zlib):** To reconstruct the bitmap from the extracted timing bytes.
- **Strings / Binwalk:** For initial memory dump inspection.
