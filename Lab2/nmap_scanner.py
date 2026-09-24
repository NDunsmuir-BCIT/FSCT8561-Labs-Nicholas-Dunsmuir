import nmap

def main():
    print("Nmap Port Scanner")
    
    try:
        nm = nmap.PortScanner()
    except nmap.PortScannerError:
        print("Error: Nmap program not found.")
        return
    except Exception as e:
        print(f"Unexpected error: {e}")
        return

    # Inputs
    target = input("Enter target host: ").strip()
    if not target:
        print("Error: Target host cannot be empty.")
        return

    try:
        start_port = int(input("Enter start port (1-65535): "))
        end_port = int(input("Enter end port (1-65535): "))
    except ValueError:
        print("Error: invalid port numbers.")
        return

    # Range Validation
    if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
        print("Error: Port numbers must be between 1 and 65535.")
        return

    if start_port > end_port:
        print("Error: Start port cannot be greater than end port.")
        return

    port_range = f"{start_port}-{end_port}"

    # Execute Scan via python-nmap
    print(f"\nScanning target: {target} for ports {port_range}...")
    try:
        nm.scan(target, port_range)
    except Exception as e:
        print(f"Error during scan: {e}")
        return

    # Extract & Parse Results Programmatically
    print(f"\nTarget: {target}")
    print(f"{'PORT':<10}{'STATE':<12}{'SERVICE':<15}{'PRODUCT/VERSION':<20}")
    print("-" * 57)

    open_count = 0
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in sorted(lport):
                port_data = nm[host][proto][port]
                state = port_data.get('state', 'unknown')
                service = port_data.get('name', 'unknown')
                product = port_data.get('product', '')
                version = port_data.get('version', '')
                ver_info = f"{product} {version}".strip() or "N/A"

                print(f"{port:<10}{state:<12}{service:<15}{ver_info:<20}")
                if state == 'open':
                    open_count += 1

    print("-" * 57)
    print(f"Scan complete. {open_count} open port(s) reported.")

if __name__ == "__main__":
    main()