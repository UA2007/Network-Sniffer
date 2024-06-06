from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        print(f"IP Packet: {ip_layer.src} -> {ip_layer.dst}")
        
    if packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)
        print(f"TCP Packet: {tcp_layer.sport} -> {tcp_layer.dport}")
        
    if packet.haslayer(UDP):
        udp_layer = packet.getlayer(UDP)
        print(f"UDP Packet: {udp_layer.sport} -> {udp_layer.dport}")

sniff(prn=packet_callback, filter="ip", count=20)
