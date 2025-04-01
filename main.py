from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

PORT = 8000  # Target port to monitor


def packet_callback(packet):
    """Callback function to process each captured packet."""
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
            size = len(packet)  # Packet size
            payload = (
                bytes(packet[TCP].payload)
                if TCP in packet
                else bytes(packet[UDP].payload) if UDP in packet else b""
            )

            print(
                f"[{proto}] {src_ip}:{src_port} → {dst_ip}:{dst_port} | Size: {size} bytes | Payload: {payload[:50]!r}"
            )


if __name__ == "__main__":
    print(f"🟢 Listening on port {PORT} for incoming and outgoing traffic...")

    # Start packet capture (requires sudo)
    sniff(
        filter=f"tcp port {PORT} or udp port {PORT}",
        prn=packet_callback,
        store=False,
        iface="lo",
    )
