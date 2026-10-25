import socket

from config import (ALLOWED_HOSTS, MAX_SCAN_SPAN, SCAN_DEFAULT_END,
                    SCAN_DEFAULT_START)


def validate_scan_request(host, start_text, end_text):
    """Check the input. Returns (ip, start, end) or raises ValueError."""
    host = host.strip().lower()

    # only localhost can be scanned
    if host not in ALLOWED_HOSTS:
        raise ValueError("Only 127.0.0.1 or localhost may be scanned.")

    try:
        start = int(start_text)
        end = int(end_text)
    except ValueError:
        raise ValueError("Ports must be whole numbers.")

    if start < 1 or start > 65535 or end < 1 or end > 65535:
        raise ValueError("Ports must be between 1 and 65535.")
    if start > end:
        raise ValueError("Start port cannot be greater than end port.")
    # cap the range so the scanner can't be used for big scans
    if end - start > MAX_SCAN_SPAN:
        raise ValueError(f"Range too large (max {MAX_SCAN_SPAN + 1} ports per scan).")

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        raise ValueError("Could not resolve host.")

    return ip, start, end


def scan_port(ip, port, timeout=0.5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    # plain TCP connect scan
    try:
        result = sock.connect_ex((ip, port))
    except OSError:
        result = 1

    sock.close()
    return result == 0


def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def scan(ip, start, end):
    open_ports = []
    for port in range(start, end + 1):
        if scan_port(ip, port):
            open_ports.append((port, service_name(port)))
    return open_ports


def run_scanner_menu():
    print("\n--- Port scan (client side, localhost only) ---")
    host = input("Target host [127.0.0.1]: ").strip()
    if host == "":
        host = "127.0.0.1"
    start = input(f"Start port [{SCAN_DEFAULT_START}]: ").strip()
    if start == "":
        start = str(SCAN_DEFAULT_START)
    end = input(f"End port [{SCAN_DEFAULT_END}]: ").strip()
    if end == "":
        end = str(SCAN_DEFAULT_END)

    try:
        ip, start, end = validate_scan_request(host, start, end)
    except ValueError as err:
        print("Scan not started:", err)
        return

    print(f"\nTarget: {ip}   Scanning TCP ports {start}-{end}...\n")
    results = scan(ip, start, end)

    print(f"{'PORT':<10}{'STATE':<10}{'LIKELY SERVICE'}")
    print("-" * 36)
    for port, service in results:
        print(f"{port:<10}{'open':<10}{service}")
    print("-" * 36)

    if len(results) > 0:
        print(f"{len(results)} open port(s) found.")
    else:
        print("No open ports found in the selected range.")
    print("An open port only shows it can be reached, not a vulnerability. "
          "Ports that did not answer are only shown as 'not open'.")