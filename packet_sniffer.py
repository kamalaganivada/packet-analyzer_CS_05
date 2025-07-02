from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        else:
            protocol = str(proto)

        print(f"\n[+] Packet captured:")
        print(f"    Source IP: {ip_src}")
        print(f"    Destination IP: {ip_dst}")
        print(f"    Protocol: {protocol}")

        if Raw in packet:
            payload = packet[Raw].load
            print(f"    Payload: {payload[:50]}...")  # Preview first 50 bytes
    else:
        print("\n[+] Non-IP Packet captured.")

print("Starting Packet Sniffer... Press CTRL+C to stop.")
sniff(prn=packet_callback, count=10)
