from collections import defaultdict
from scapy.all import rdpcap, IP, TCP, UDP

def main():
    pcap_path = "botnet-capture-20110812-rbot.pcap"
    packets = rdpcap(pcap_path)

    tcp_count = 0
    udp_count = 0
    ip_timestamps = defaultdict(list)
    alerted_ips = set()

    # Sort packets by timestamp to ensure proper sliding window functionality
    sorted_packets = sorted(packets, key=lambda p: float(p.time) if hasattr(p, 'time') else 0)

    for pkt in sorted_packets:
        if IP in pkt and (TCP in pkt or UDP in pkt):
            if TCP in pkt:
                tcp_count += 1
            if UDP in pkt:
                udp_count += 1

            src_ip = pkt[IP].src
            current_time = float(pkt.time)

            # Slide window: Keep timestamps within the last 5 seconds
            ip_timestamps[src_ip] = [t for t in ip_timestamps[src_ip] if current_time - t <= 5.0]
            ip_timestamps[src_ip].append(current_time)

            # Alert condition: > 20 packets within 5 seconds
            if len(ip_timestamps[src_ip]) > 20 and src_ip not in alerted_ips:
                print(f"[ALERT] Unusually frequent traffic detected from Source IP: {src_ip}")
                alerted_ips.add(src_ip)

    print("\n--- Detection Summary ---")
    print(f"Total TCP packets: {tcp_count}")
    print(f"Total UDP packets: {udp_count}")
    print(f"Number of suspicious IPs detected: {len(alerted_ips)}")

if __name__ == "__main__":
    main()
    