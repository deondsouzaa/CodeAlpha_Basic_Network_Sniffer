# CodeAlpha — Basic Network Sniffer

A minimal Python network sniffer for capturing and inspecting packets using **Scapy**.  
It prints source/destination IPs, identifies the L4 protocol (TCP/UDP/ICMP), shows a preview of any text payload, and simultaneously saves every packet to a `capture.pcap` file for later analysis (e.g., in Wireshark).

---

## ✨ Features
- Captures live packets and writes them to `capture.pcap`.
- Prints for each IP packet:
  - Source IP → Destination IP
  - Detected L4 protocol: TCP / UDP / ICMP (or protocol number)
  - A short preview of the payload (decoded as text when possible)
- Stops automatically after a fixed number of packets (for easy demos).

---

## 🧰 Requirements
- Python 3.8+
- Linux (tested on Kali)
- Root privileges (or equivalent capabilities) to sniff packets
- Python package: `scapy`

Install on Kali (either approach works):
```bash
# APT package (recommended on Kali):
sudo apt update && sudo apt install -y python3-scapy

# OR via pip in a virtual environment:
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

> The script writes all captured packets to **`capture.pcap`** in the same folder.

---

## ▶️ Usage
Run with elevated privileges so packet capture works correctly.
```bash
sudo python3 sniff_test.py
```
Example console output:
```
[+] 192.168.1.5 --> 172.217.168.142 | Protocol: TCP
    Payload (text): 'GET / HTTP/1.1\r\nHost: example.com...'
[+] 192.168.1.5 --> 1.1.1.1 | Protocol: ICMP
    Payload (raw): b'\x08\x00\xf7\xff...'
```
A `capture.pcap` file is produced in the project directory for offline analysis.

---

## 📝 How it works (high level)
- Uses `scapy.sniff` to listen on the `eth0` interface and call a `show(pkt)` handler.
- Each IP packet is inspected to determine the L4 protocol (`TCP`, `UDP`, `ICMP`) and printed with basic info.
- If a Raw payload exists, the code decodes and previews up to ~80 characters (or shows raw bytes).
- Every packet is written to `capture.pcap` via `PcapWriter` for tools like Wireshark.

> **Interface note:** The script is hard-coded for `eth0`. Ensure your active interface is actually `eth0` (common in VMs). If your system uses another interface name (e.g., `wlan0`/`enp0s3`), configure your environment so `eth0` is available. The script must remain unchanged, as requested.

---

## ⚖️ Legal & Ethical Use
Only sniff traffic on networks you **own** or have **explicit written permission** to test. Intercepting others’ traffic without consent may be illegal in your jurisdiction. Use responsibly for learning and authorized security testing only.

---

## 🧪 Troubleshooting
- **Permission denied / no packets captured:** Run with `sudo`.  
- **`eth0` not found:** Verify your interface with `ip a`. Use an environment where `eth0` exists (e.g., VM settings).  
- **`capture.pcap` is empty:** Make sure there is actual traffic during capture (browse the web, ping, etc.).  
- **Wireshark can’t open the file:** Ensure the script finished writing (it syncs as it goes).

---

## 📜 License
You can keep this closed for assignment submission or add a license of your choice (e.g., MIT).

