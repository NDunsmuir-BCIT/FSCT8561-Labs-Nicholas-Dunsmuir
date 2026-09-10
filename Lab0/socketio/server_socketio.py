from aiohttp import web
import socketio

sio = socketio.AsyncServer()
app = web.Application()
sio.attach(app)


async def index(request):
    return web.Response(
        text="Socket.IO Server Running",
        content_type="text/html"
    )


@sio.event
async def connect(sid, environ):
    print("Client connected:", sid)


@sio.on("message")
async def receive_message(sid, data):
    print("Message received from client:", data)


@sio.event
async def disconnect(sid):
    print("Client disconnected:", sid)


app.router.add_get("/", index)


if __name__ == "__main__":
    print("Socket.IO server running...")
    web.run_app(app, port=8080) 