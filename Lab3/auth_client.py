import socket
from getpass import getpass

HOST = "127.0.0.1"
PORT = 8000


def run_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_socket.connect((HOST, PORT))
        print(f"Connected to authentication server at {HOST}:{PORT}")

        # Collect user credentials
        username = input("Enter username: ").strip()
        # getpass prevents the password from echoing on screen
        password = getpass("Enter password: ").strip()

        # Step 1: Transmit AUTH message
        auth_message = f"AUTH|{username}|{password}"
        client_socket.send(auth_message.encode())

        # Receive response from server
        response = client_socket.recv(1024).decode().strip()
        print("Server response:", response)

        # Step 2: Handle OTP step if password was verified
        if response == "OTP_REQUIRED":
            otp = input("Enter 6-digit OTP: ").strip()
            otp_message = f"OTP|{otp}"
            client_socket.send(otp_message.encode())

            final_response = client_socket.recv(1024).decode().strip()
            print("Server final response:", final_response)

            if final_response == "ACCESS_GRANTED":
                print("\n[***] Authentication successful! Access granted. [***]")
            else:
                print("\n[-] Authentication failed at OTP stage.")
        else:
            print("\n[-] Authentication failed at Password stage.")

        # Optional clean disconnect signal
        client_socket.send("EXIT|".encode())

    except ConnectionRefusedError:
        print("[!] Could not connect to server.")
    except Exception as e:
        print(f"[!] Network error: {e}")
    finally:
        client_socket.close()
        print("Client socket closed.")


if __name__ == "__main__":
    run_client()