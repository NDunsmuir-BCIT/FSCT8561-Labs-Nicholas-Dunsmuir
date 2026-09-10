import socketio
import time

sio = socketio.Client()


@sio.event
def connect():
    print("Connection established")


@sio.event
def disconnect():
    print("Disconnected from server")


sio.connect("http://localhost:8080")

message = "Hello Server"
print("Sending message:", message)

sio.emit("message", message)

time.sleep(1)

sio.disconnect()