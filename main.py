import asyncio
from contextlib import asynccontextmanager
from queue import Queue
from typing import Union

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from scapy.all import AsyncSniffer, Packet
from scapy.layers.inet import IP, TCP, UDP

messages_queue: Queue[str] = Queue()
main_loop = None


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)


manager = ConnectionManager()


def packet_callback(packet: Packet):
    print("sniffing")
    if IP in packet:  # Ensure the packet has an IP layer

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "OTHER"

        # Get port information
        src_port = (
            packet[TCP].sport
            if TCP in packet
            else packet[UDP].sport if UDP in packet else None
        )
        dst_port = (
            packet[TCP].dport
            if TCP in packet
            else packet[UDP].dport if UDP in packet else None
        )

        # Only print if the packet is related to port 3000
        if src_port == PORT or dst_port == PORT:
            print("connections", len(manager.active_connections))
            size = len(packet)  # Packet size
            payload = (
                bytes(packet[TCP].payload)
                if TCP in packet
                else bytes(packet[UDP].payload) if UDP in packet else b""
            )
            message = f"[{proto}] {src_ip}:{src_port} → {dst_ip}:{dst_port} | Size: {size} bytes | Payload: {payload[:50]!r}"

            messages_queue.put(message)
            if main_loop:
                asyncio.run_coroutine_threadsafe(manager.broadcast(message), main_loop)


PORT = 8000
sniffer = AsyncSniffer(
    filter=f"tcp port {PORT} or udp port {PORT}",
    prn=packet_callback,
    store=False,
    iface="lo",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global main_loop
    main_loop = asyncio.get_event_loop()
    yield
    if sniffer.running:
        sniffer.stop()


app = FastAPI(lifespan=lifespan)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await manager.connect(websocket)

    try:
        while True:
            data = await websocket.receive_text()

            if data == "start":
                sniffer.start()

            if data == "stop" and sniffer.running:
                sniffer.stop()

            await manager.broadcast(f"Message text was: {data}")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        await manager.broadcast(f"Client left the chat")
