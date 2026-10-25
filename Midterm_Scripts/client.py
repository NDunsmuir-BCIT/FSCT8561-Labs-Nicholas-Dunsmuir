import json
import socket
import sys
from getpass import getpass

from config import HOST, PORT, MAX_PASSWORD_LEN, USERNAME_RE, OTP_RE
from http_checker import run_checker_menu
from port_scanner import run_scanner_menu


def send_request(sock, text):
    """Send one message and return the server's one-line reply."""
    sock.sendall((text + "\n").encode())

    reply = b""
    while not reply.endswith(b"\n"):
        ch = sock.recv(1)
        if ch == b"":
            raise ConnectionError("server closed the connection")
        reply += ch
        # cap the reply size to a maximum
        if len(reply) > 65536:
            raise ConnectionError("reply too long")
    return reply.decode(errors="replace").strip()


def login(sock):
    """Ask for username, password and OTP. Returns True if access is granted."""
    while True:
        username = input("\nUsername (blank to quit): ").strip()
        if username == "":
            return False
        # check input on the client side too as well as server side
        if not USERNAME_RE.fullmatch(username):
            print("Usernames are 1-32 letters, digits or underscore.")
            continue

# getpass hides the password while typing so it doesn't show on screen
        password = getpass("Password: ")
        if len(password) == 0 or len(password) > MAX_PASSWORD_LEN:
            print("Invalid password format.")
            continue

        reply = send_request(sock, "AUTH|" + username + "|" + password)

        if reply == "OTP_REQUIRED":
            otp = input("6-digit OTP: ").strip()
            while not OTP_RE.fullmatch(otp):
                otp = input("OTP must be exactly 6 digits: ").strip()

            reply = send_request(sock, "OTP|" + otp)
            if reply == "ACCESS_GRANTED":
                print("\nAccess granted.")
                return True

        print("Server:", reply)
        if reply == "ERROR|Locked":
            print("Too many failed attempts. The server closed the connection.")
            return False


def show_pcap_results(reply):
    if not reply.startswith("OK|"):
        print("Server:", reply)
        return

    try:
        data = json.loads(reply[3:])
        print(f"\nPCAP summary: {data['total']} packets "
              f"({data['tcp']} TCP, {data['udp']} UDP)")

        if len(data["alerts"]) == 0:
            print("No suspicious patterns detected.")
            return

        print(f"\n{'SOURCE IP':<16}{'PATTERN':<16}DETAIL")
        print("-" * 62)
        for alert in data["alerts"]:
            print(f"{alert['src']:<16}{alert['type']:<16}{alert['detail']}")
        print("\nAlerts mean unusual traffic worth review, not proof of an attack.")
    except (ValueError, KeyError, TypeError):
        print("Could not read the server's analysis result.")


def menu(sock):
    while True:
        print("\n=== Operation Sentinel ===")
        print("1. Analyze PCAP (server)")
        print("2. Scan TCP ports (local)")
        print("3. Check test website (local)")
        print("4. Exit")
        choice = input("Choose 1-4: ").strip()

        if choice == "1":
            show_pcap_results(send_request(sock, "PCAP|"))
        elif choice == "2":
            run_scanner_menu()
        elif choice == "3":
            run_checker_menu()
        elif choice == "4":
            print("Server:", send_request(sock, "EXIT|"))
            return
        else:
            print("Please enter a number from 1 to 4.")


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)

    try:
        sock.connect((HOST, PORT))
    except OSError:
        print(f"Could not connect to the server at {HOST}:{PORT}. Is server.py running?")
        sock.close()
        return 1

    print(f"Connected to Operation Sentinel server at {HOST}:{PORT}")

    try:
        if login(sock):
            menu(sock)
    except (ConnectionError, socket.timeout) as err:
        print(f"\nConnection lost: {err}")
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nExiting.")
    finally:
        sock.close()
        print("Client socket closed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())