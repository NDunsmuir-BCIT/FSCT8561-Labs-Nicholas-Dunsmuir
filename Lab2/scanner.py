import socket

def scan_port(target_ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    result = sock.connect_ex((target_ip, port))
    sock.close()
    return result == 0

def get_service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"

def main():
    print("RAw Socket Port Scanner")
    
    # Target resolution
    target_input = input("Enter target host: ").strip()
    if not target_input:
        print("Error: Target host cannot be empty.")
        return

    try:
        target_ip = socket.gethostbyname(target_input)
    except socket.gaierror:
        print(f"Error: Unable to resolve hostname/IP '{target_input}'.")
        return

    # Port range input & validation
    try:
        start_port = int(input("Enter start port (1-65535): "))
        end_port = int(input("Enter end port (1-65535): "))
    except ValueError:
        print("Error: Port numbers must be integers.")
        return

    if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
        print("Error: Port numbers must be between 1 and 65535.")
        return

    if start_port > end_port:
        print("Error: Start port cannot be greater than end port.")
        return

    if (end_port - start_port) > 100:
        print("Error: Scan range exceeds maximum limit of 100 ports.")
        return

    # Execute scan
    print(f"\nTarget: {target_ip}")
    print(f"Scanning TCP ports {start_port}–{end_port}...\n")
    
    open_ports = []
    print(f"{'PORT':<10}{'STATE':<12}{'SERVICE':<15}")
    print("-" * 37)

    for port in range(start_port, end_port + 1):
        if scan_port(target_ip, port):
            service = get_service_name(port)
            print(f"{port:<10}{'open':<12}{service:<15}")
            open_ports.append(port)

    print("-" * 37)
    print("Scan complete.")
    if open_ports:
        print(f"{len(open_ports)} open port(s) found.")
    else:
        print("No open ports found in the selected range.")

if __name__ == "__main__":
    main()