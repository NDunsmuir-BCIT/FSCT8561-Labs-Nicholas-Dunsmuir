import socket
import threading

HOST = "127.0.0.1"
PORT = 12345

clients = {}  # Maps socket -> username
lock = threading.Lock()

def broadcast(message, sender_socket=None):
    """Sends a message to all connected clients except the sender."""
    with lock:
        for client_sock in list(clients.keys()):
            if client_sock != sender_socket:
                try:
                    client_sock.send(message.encode())
                except:
                    client_sock.close()
                    del clients[client_sock]

def handle_client(client_socket, client_address):
    print(f"[NEW CONNECTION] Connected by {client_address}")
    username = None
    
    try:
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
                
            message = data.decode()
            if "|" not in message:
                client_socket.send("ERROR|Invalid format".encode())
                continue
                
            command, content = message.split("|", 1)
            
            if command == "HELLO":
                username = content
                with lock:
                    clients[client_socket] = username
                print(f"[REGISTERED] {client_address} set username to '{username}'")
                client_socket.send(f"OK|Hello {username}".encode())
                
            elif command == "MSG":
                if not username:
                    client_socket.send("ERROR|HELLO required first".encode())
                    continue
                
                formatted_msg = f"{username}: {content}"
                print(f"[CHAT] {formatted_msg}")
                # Acknowledge sender
                client_socket.send("OK|Message sent".encode())
                # Broadcast to all other clients
                broadcast(formatted_msg, sender_socket=client_socket)
                
            elif command == "EXIT":
                client_socket.send("OK|Goodbye".encode())
                break
                
            else:
                client_socket.send("ERROR|Unknown command".encode())
                
    except Exception as e:
        print(f"[DISCONNECT ERROR] Client {client_address} error: {e}")
    finally:
        with lock:
            if client_socket in clients:
                del clients[client_socket]
        client_socket.close()
        print(f"[CLOSED] Connection with {client_address} closed.")

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(5)
print("Lab1 Challenge server initiating.....")

while True:
    client_socket, client_address = server_socket.accept()
    thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
    thread.daemon = True
    thread.start()