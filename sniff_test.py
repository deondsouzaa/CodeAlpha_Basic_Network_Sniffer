from scapy.all import sniff, IP, TCP, UDP, ICMP, PcapWriter

writer = PcapWriter("capture.pcap", append=True, sync=True)

def show(pkt):
    writer.write(pkt)  
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        if   TCP in pkt:  l4 = "TCP"
        elif UDP in pkt:  l4 = "UDP"
        elif ICMP in pkt: l4 = "ICMP"
        else:             l4 = str(pkt[IP].proto)
        print(f"[+] {ip_src} --> {ip_dst} | Protocol: {l4}")
        if pkt.haslayer("Raw"):
            payload = pkt["Raw"].load
            try:
                text = payload.decode(errors="ignore")
                print(f"    Payload (text): {text[:80]!r}")
            except:
                print(f"    Payload (raw): {payload[:50]!r}")

if __name__ == "__main__":
    sniff(iface="eth0", store=False, prn=show, count=20)
