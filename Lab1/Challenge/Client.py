import socket
import threading
import sys

HOST = "127.0.0.1"
PORT = 12345

def listen_for_messages(sock):
    """Background thread to print incoming broadcast messages."""
    while True:
        try:
            data = sock.recv(1024)
            if not data:
                break
            print(f"\n{data.decode()}\nEnter message or type EXIT to leave: ", end="")
        except:
            break

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

username = input("Enter your username: ")
client_socket.send(f"HELLO|{username}".encode())
response = client_socket.recv(1024)
print("Server:", response.decode())

# Start background thread to receive broadcasted messages from other users
listener_thread = threading.Thread(target=listen_for_messages, args=(client_socket,))
listener_thread.daemon = True
listener_thread.start()

while True:
    message = input("Enter message or type EXIT to leave: ")
    if message.upper() == "EXIT":
        client_socket.send("EXIT|".encode())
        break
        
    client_socket.send(f"MSG|{message}".encode())

client_socket.close()
print("Disconnected")
sys.exit()