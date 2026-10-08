from scapy.all import rdpcap, IP, TCP, UDP

def main():
    pcap_path = "botnet-capture-20110812-rbot.pcap"
    packets = rdpcap(pcap_path)

    tcp_count = 0
    udp_count = 0
    displayed_count = 0

    print("--- First 20 IPv4 TCP/UDP Packets ---")
    for pkt in packets:
        if IP in pkt:
            is_tcp = TCP in pkt
            is_udp = UDP in pkt

            if is_tcp:
                tcp_count += 1
            if is_udp:
                udp_count += 1

            if (is_tcp or is_udp) and displayed_count < 20:
                proto = "TCP" if is_tcp else "UDP"
                layer = pkt[TCP] if is_tcp else pkt[UDP]
                
                print(f"Source: {pkt[IP].src} Destination: {pkt[IP].dst} "
                      f"Protocol: {proto} Source port: {layer.sport} Destination port: {layer.dport}")
                displayed_count += 1

    print("\n--- Summary ---")
    print(f"Total TCP packets: {tcp_count}")
    print(f"Total UDP packets: {udp_count}")

if __name__ == "__main__":
    main()