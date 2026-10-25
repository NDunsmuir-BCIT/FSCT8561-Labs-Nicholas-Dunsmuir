import json

from scapy.all import rdpcap, IP, TCP, UDP

from config import PCAP_FILE
# thresholds per source IP inside a 5 second window:
# more than 20 packets in 5s is way above a normal host output
# SYNs to 15+ different ports in 5s could be a port scan
# 10+ SYNs to the same port in 5s looks like repeated connection attempts
WINDOW = 5
RATE_THRESHOLD = 20
SCAN_PORTS = 15
REPEAT_SYNS = 10


class AnalysisError(Exception):
    pass


def extract_records(packets):
    records = []
    for pkt in packets:
        if IP not in pkt:
            continue

        if TCP in pkt:
            flags = int(pkt[TCP].flags)
            # only count SYN without ACK 
            is_syn = (flags & 0x02) != 0 and (flags & 0x10) == 0
            records.append((float(pkt.time), pkt[IP].src, "TCP", int(pkt[TCP].dport), is_syn))
        elif UDP in pkt:
            records.append((float(pkt.time), pkt[IP].src, "UDP", int(pkt[UDP].dport), False))

    # the window needs the packets in time order
    records.sort(key=lambda r: r[0])
    return records

# each source only gets each alert once
def detect(records):
    recent = {}         
    alerted = set()     
    alerts = []

    for ts, src, proto, dport, is_syn in records:
        if src not in recent:
            recent[src] = []
        recent[src].append((ts, dport, is_syn))

# drop packets older than 5 seconds
        recent[src] = [p for p in recent[src] if ts - p[0] <= WINDOW]
        window = recent[src]

        syn_ports = {}
        for p in window:
            if p[2]:
                syn_ports[p[1]] = syn_ports.get(p[1], 0) + 1

        if len(window) > RATE_THRESHOLD and (src, "high_rate") not in alerted:
            alerted.add((src, "high_rate"))
            alerts.append({"src": src, "type": "high_rate",
                           "detail": f"{len(window)} packets in {WINDOW}s"})

        if len(syn_ports) >= SCAN_PORTS and (src, "port_scan") not in alerted:
            alerted.add((src, "port_scan"))
            alerts.append({"src": src, "type": "port_scan",
                           "detail": f"SYNs to {len(syn_ports)} different ports in {WINDOW}s"})

        if len(syn_ports) > 0:
            top_port = max(syn_ports, key=syn_ports.get)
            if syn_ports[top_port] >= REPEAT_SYNS and (src, "repeated_port") not in alerted:
                alerted.add((src, "repeated_port"))
                alerts.append({"src": src, "type": "repeated_port",
                               "detail": f"{syn_ports[top_port]} SYNs to port {top_port} in {WINDOW}s"})

    alerts.sort(key=lambda a: a["src"])
    return alerts


def analyze(path=PCAP_FILE):
    try:
        packets = rdpcap(path)
    # a missing or corrupt file outputs an error instead of crashing the server
    except Exception:
        raise AnalysisError("cannot read capture")

    if len(packets) == 0:
        raise AnalysisError("capture is empty")

    try:
        records = extract_records(packets)
        alerts = detect(records)
    except Exception:
        raise AnalysisError("cannot analyze capture")

    tcp_count = 0
    udp_count = 0
    for r in records:
        if r[2] == "TCP":
            tcp_count += 1
        else:
            udp_count += 1

# only counts and alerts get returned not raw payloads
    return {"total": len(packets), "tcp": tcp_count, "udp": udp_count, "alerts": alerts}


def to_json_line(summary):
    return json.dumps(summary, separators=(",", ":"))


if __name__ == "__main__":
    print(json.dumps(analyze(), indent=2))