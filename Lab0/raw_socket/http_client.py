import socket

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("example.com", 80))

request = (
    "GET / HTTP/1.1\r\n"
    "Host: example.com\r\n"
    "Connection: close\r\n"
    "\r\n"
)

client.send(request.encode())

response = b""
while True:
    data = client.recv(4096)
    if not data:
        break
    response += data

print(response.decode(errors="replace"))
client.close()