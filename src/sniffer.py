import json
from queue import Queue
from threading import Event

from scapy.all import Packet, sniff
from scapy.layers.inet import IP, TCP, UDP

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
            queue.put(packet.json())
            decoded_packet = recursively_parse_payload(decoded_packet)

            print("-------------------------------\n")
            print(packet.json())
            # if len(string_data) > 0:
            # print(
            #    f"port: {src_port} - target: {dst_port} - \npyload: {string_data}"
            # )

            # print(
            #    f"[{proto}] {src_ip}:{src_port} → {dst_ip}:{dst_port} | Size: {size} bytes | Payload: {payload[:50]!r}"
            # )


def sniff_network(stop_sniff_event: Event):
    sniff(
        filter=f"tcp port {PORT} or udp port {PORT}",
        prn=sniffer,
        store=False,
        iface="lo",
        stop_filter=lambda _: stop_sniff_event.is_set(),
        # count=60,
    )


if __name__ == "__main__":
    print(f"🟢 Listening on port {PORT} for incoming and outgoing traffic...")

    # Start packet capture (requires sudo)
    sniff(
        filter=f"tcp port {PORT} or udp port {PORT}",
        prn=sniffer,
        store=False,
        iface="lo",
        count=60,
    )
