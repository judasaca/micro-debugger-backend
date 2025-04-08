import asyncio
import json
import threading
from contextlib import asynccontextmanager
from typing import List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from scapy.all import Packet, sniff
from scapy.layers.inet import IP, TCP, UDP

main_event_loop = None


@asynccontextmanager
async def lifespan():

    global main_event_loop
    main_event_loop = asyncio.get_event_loop()

    yield


app = FastAPI()


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_packet_summary(self, message: str, websocket: WebSocket):
        print("sending packet")
        try:
            await websocket.send_text(message)
        except WebSocketDisconnect:
            self.disconnect(websocket)


manager = ConnectionManager()
sniffer_process = None
stop_sniffing_event = threading.Event()

PORT = 8000


def packet_callback(packet: Packet):
    print("sniffing...")
    summary = packet.summary()
    if packet.haslayer(IP):  # Ensure the packet has an IP layer
        print("layer!")
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
        print("ports", src_port, dst_port)
        if src_port == PORT or dst_port == PORT:
            print("port matching")
            if manager.active_connections and main_event_loop:
                print("active connections")
                for connection in manager.active_connections:
                    print("sending corutine")

                    asyncio.run_coroutine_threadsafe(
                        manager.send_packet_summary(
                            json.dumps({"summary": summary}), connection
                        ),
                        main_event_loop,
                    )
    return not stop_sniffing_event.is_set()


def start_sniffer():
    global sniffer_process, stop_sniffing_event
    stop_sniffing_event.clear()
    try:
        sniff(
            filter=f"tcp port {PORT} or udp port {PORT}",
            prn=packet_callback,
            stop_filter=lambda _: stop_sniffing_event.is_set(),
            store=False,
            iface="lo",
        )
    except Exception as e:
        print(f"Sniffing error: {e}")
    finally:
        print("Sniffing stopped.")
        sniffer_process = None


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "start":
                global sniffer_process
                if sniffer_process is None:
                    print("Starting sniffer...")
                    sniffer_process = threading.Thread(target=start_sniffer)
                    sniffer_process.daemon = True
                    sniffer_process.start()
                else:
                    await websocket.send_text(
                        json.dumps({"status": "Sniffer already running"})
                    )
            elif data == "stop":
                global stop_sniffing_event
                if sniffer_process and sniffer_process.is_alive():
                    print("Stopping sniffer...")
                    stop_sniffing_event.set()
                    # No need to explicitly join here, it will stop on its own
                else:
                    await websocket.send_text(
                        json.dumps({"status": "Sniffer not running"})
                    )
            else:
                await websocket.send_text(json.dumps({"error": "Invalid command"}))
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        if (
            manager.active_connections == 0
            and sniffer_process
            and sniffer_process.is_alive()
        ):
            print("All connections closed, stopping sniffer...")
            stop_sniffing_event.set()
    except Exception as e:
        print(f"WebSocket error: {e}")
        manager.disconnect(websocket)
        if (
            manager.active_connections == 0
            and sniffer_process
            and sniffer_process.is_alive()
        ):
            print("WebSocket exception, stopping sniffer...")
            stop_sniffing_event.set()


import signal
import sys


def handle_shutdown(*args, **kwargs):
    global stop_sniffing_event, sniffer_process
    print("FastAPI server shutting down...")
    stop_sniffing_event.set()
    if sniffer_process and sniffer_process.is_alive():
        print("Waiting for sniffer to stop...")
        sniffer_process.join(timeout=5)
        if sniffer_process.is_alive():
            print("Sniffer did not stop gracefully, it might still be running.")
    sys.exit(0)


signal.signal(signal.SIGINT, handle_shutdown)
signal.signal(signal.SIGTERM, handle_shutdown)

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001)
