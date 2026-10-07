import hashlib
import socket
import pyotp


# Helper Cryptographic and OTP Functions
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(password, stored_hash):
    return hash_password(password) == stored_hash


def verify_otp(secret, otp):
    totp = pyotp.TOTP(secret)
    return totp.verify(otp)


# User Database (Stores password hashes & static Base32 TOTP secrets, no plaintext passwords)
users = {
    "alice": {
        "password_hash": hash_password("Cyber123!"),
        "totp_secret": "JBSWY3DPEHPK3PXP",  # Test Base32 secret
    },
    "bob": {
        "password_hash": hash_password("SecurePass2026!"),
        "totp_secret": "KVKFKRCPNZQUYMLX",
    },
}

HOST = "127.0.0.1"
PORT = 8000
MAX_FAILED_ATTEMPTS = 3

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server_socket.bind((HOST, PORT))
server_socket.listen(1)

print("Server is waiting for a connection...")

client_socket, client_address = server_socket.accept()

print("Connected by:", client_address)

# State and Failure Counter Tracking
authenticated_user = None
password_verified = False
failed_attempts = 0
connected = True

while connected:

    try:
        data = client_socket.recv(1024)

        if not data:
            print("Client disconnected unexpectedly")
            break

        message = data.decode().strip()

        print("Received:", message)

        if "|" not in message:
            failed_attempts += 1
            client_socket.send(
                f"ERROR|Invalid command format (Failed attempts: {failed_attempts}/{MAX_FAILED_ATTEMPTS})".encode()
            )
            if failed_attempts >= MAX_FAILED_ATTEMPTS:
                client_socket.send(
                    "ERROR|Too many failed attempts. Access blocked.".encode()
                )
                connected = False
            continue

        parts = message.split("|", 2)
        command = parts[0].upper()

        if command == "AUTH":

            if len(parts) < 3:
                failed_attempts += 1
                client_socket.send(
                    f"ERROR|AUTH requires username and password (Failed attempts: {failed_attempts}/{MAX_FAILED_ATTEMPTS})".encode()
                )
            else:
                user_input = parts[1]
                pass_input = parts[2]

                # Check if username exists and password matches
                if user_input in users and verify_password(
                    pass_input, users[user_input]["password_hash"]
                ):
                    password_verified = True
                    authenticated_user = user_input
                    print(f"Password verified for user: {authenticated_user}")
                    client_socket.send("OTP_REQUIRED".encode())
                else:
                    failed_attempts += 1
                    password_verified = False
                    authenticated_user = None
                    print(
                        f"Password verification failed for user: {user_input}"
                    )
                    client_socket.send(
                        f"ACCESS_DENIED|Invalid credentials (Failed attempts: {failed_attempts}/{MAX_FAILED_ATTEMPTS})".encode()
                    )

        elif command == "OTP":

            if len(parts) < 2:
                failed_attempts += 1
                client_socket.send(
                    f"ERROR|OTP code required (Failed attempts: {failed_attempts}/{MAX_FAILED_ATTEMPTS})".encode()
                )

            # Prevent OTP submission prior to successful password verification
            elif not password_verified or authenticated_user is None:
                failed_attempts += 1
                print("OTP rejected: Password stage not completed first")
                client_socket.send(
                    f"ERROR|OTP submitted before password verification (Failed attempts: {failed_attempts}/{MAX_FAILED_ATTEMPTS})".encode()
                )

            else:
                otp_code = parts[1]
                user_secret = users[authenticated_user]["totp_secret"]

                if verify_otp(user_secret, otp_code):
                    print(f"ACCESS_GRANTED for user: {authenticated_user}")
                    client_socket.send("ACCESS_GRANTED".encode())
                    failed_attempts = 0  # Reset counter on successful authentication
                else:
                    failed_attempts += 1
                    print(f"OTP verification failed for {authenticated_user}")
                    client_socket.send(
                        f"ACCESS_DENIED|Invalid or expired OTP (Failed attempts: {failed_attempts}/{MAX_FAILED_ATTEMPTS})".encode()
                    )

        elif command == "EXIT":

            client_socket.send("OK|Goodbye".encode())
            connected = False

        else:
            failed_attempts += 1
            client_socket.send(
                f"ERROR|Unknown command (Failed attempts: {failed_attempts}/{MAX_FAILED_ATTEMPTS})".encode()
            )

        # Enforce maximum failed attempts limit (Challenge / Part 17)
        if failed_attempts >= MAX_FAILED_ATTEMPTS:
            print(
                f"Locking out {client_address} after {failed_attempts} failed attempts."
            )
            client_socket.send(
                "\nERROR|Maximum failed attempts exceeded. Access blocked.".encode()
            )
            connected = False

    except ConnectionResetError:
        print("Connection reset by client")
        break

client_socket.close()
server_socket.close()

print("Server closed")