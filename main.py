import asyncio
import json
from contextlib import asynccontextmanager
from queue import Empty, Queue
from threading import Event, Thread
from typing import Union

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from scapy.all import Packet, sniff
from scapy.layers.inet import IP, TCP, UDP

from src.socket_manager import ConnectionManager

packet_queue: Queue[str] = Queue()
sniff_thread = None
stop_sniff_event = Event()
sniffing_active = Event()

manager = ConnectionManager()


def stop_sniffer():
    print("requesting stop")
    stop_sniff_event.set()
    sniffing_active.clear()
    print("[*] Sniffer stop requested.")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load the ML model
    yield
    # Clean up the ML models and release the resources
    stop_sniffer()


app = FastAPI(lifespan=lifespan)


PORT = 8000  # Target port to monitor


def recursively_parse_payload(pkt_dict):
    payload = pkt_dict.get("payload")
    if isinstance(payload, str):
        try:
            payload_dict = json.loads(payload)
            pkt_dict["payload"] = recursively_parse_payload(payload_dict)
        except json.JSONDecodeError:
            pass  # payload is not a JSON string
    return pkt_dict


def sniffer(packet: Packet):
    """Callback function to process each captured packet."""
    # print("printing", len(packet), packet[TCP].payload, packet[IP].src, packet[IP].dst)
    print("sniffer running")

    if packet.haslayer(IP):  # Ensure the packet has an IP layer
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = (
            "TCP"
            if packet.haslayer(TCP)
            else "UDP" if packet.haslayer(UDP) else "OTHER"
        )

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
            size = len(packet)  # Packet size
            payload = (
                bytes(packet[TCP].payload)
                if TCP in packet
                else bytes(packet[UDP].payload) if UDP in packet else b""
            )
            string_data = payload.decode("utf-8", errors="replace")
            decoded_packet = json.loads(packet.json())
            print("sending data to queue")
            packet_queue.put(packet.json())
            decoded_packet = recursively_parse_payload(decoded_packet)


def sniff_network():
    sniff(
        filter=f"tcp port {PORT} or udp port {PORT}",
        prn=sniffer,
        store=False,
        iface="lo",
        stop_filter=lambda _: stop_sniff_event.is_set(),
    )


def start_sniffer():
    global sniff_thread, stop_sniff_event
    if sniff_thread is None or not sniff_thread.is_alive():
        stop_sniff_event.clear()
        sniffing_active.set()

        sniff_thread = Thread(target=sniff_network, daemon=True)
        sniff_thread.start()
        print("[*] Sniffer started.")


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await manager.connect(websocket)

    send_task = None

    try:

        async def send_packets():
            while sniffing_active.is_set():
                print(sniffing_active)
                print("sending packets")
                try:
                    print("getting data from queue")
                    data = packet_queue.get(timeout=1)
                    # print("data got", data)
                    await websocket.send_text(data)
                    print("data sent")
                except Empty:
                    break
                except Exception as e:
                    print(f"[!] Error sending packet: {e}")
                    break

            print("--------------- finished send package -----")

        while True:
            print("socket looop")
            data = await websocket.receive_text()
            if data == "start":

                start_sniffer()
                if send_task is None or send_task.done():
                    send_task = asyncio.create_task(send_packets())

            elif data == "stop":
                stop_sniffer()

            elif data == "close":
                break
            await manager.broadcast(f"Message text was: {data}")

    except WebSocketDisconnect:
        print("disconnection")
        manager.disconnect(websocket)
        await manager.broadcast(f"Client left the chat")

    except Exception as e:
        print("Unhandled error", e)

    finally:
        print("finally")
        manager.disconnect(websocket)
        stop_sniffer()

        if send_task:
            send_task.cancel()
            try:
                await send_task
            except:
                pass
