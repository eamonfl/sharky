import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
from threading import Lock, Thread
from typing import Dict, Tuple, Any

# Initialize a lock for thread-safe operations on the packet dictionary
packet_dict_lock = Lock()

def capture_packets(packet_dict: Dict[Tuple[str, str], int], stop_event, iface: str) -> None:
    """
    Capture network packets on a specified interface and update the packet_dict
    with the count of packets for each unique connection and protocol.

    Args:
        packet_dict (Dict[Tuple[str, str], int]): Dictionary to store the count of packets for each connection.
        stop_event: Event object used to signal when to stop packet capturing.
        iface (str): Network interface on which to capture packets.
    """
    def packet_callback(packet) -> None:
        if IP in packet:
            ip_src, ip_dst = packet[IP].src, packet[IP].dst
            proto, sport, dport = "Other", None, None

            if TCP in packet:
                proto, sport, dport = "TCP", packet[TCP].sport, packet[TCP].dport
            elif UDP in packet:
                proto, sport, dport = "UDP", packet[UDP].sport, packet[UDP].dport

            connection = f"{ip_src}:{sport} -> {ip_dst}:{dport}"

            with packet_dict_lock:
                packet_dict[(connection, proto)] += 1

        scapy.sniff(prn=packet_callback, stop_filter=lambda _: stop_event.is_set(), store=False, iface=iface)

def start_capture(iface: str, packet_dict: Dict[Tuple[str, str], int], stop_event) -> None:
    """
    Start capturing packets on a specified interface.

    Args:
        iface (str): Network interface on which to capture packets.
        packet_dict (Dict[Tuple[str, str], int]): Dictionary to store the count of packets for each connection.
        stop_event: Event object used to signal when to stop packet capturing.
    """
    packet_dict.clear()
    stop_event.clear()
    capture_thread = Thread(target=capture_packets, args=(packet_dict, stop_event, iface), daemon=True)
    capture_thread.start()

def stop_capture(stop_event) -> None:
    """
    Stop capturing packets by setting the stop event.

    Args:
        stop_event: Event object used to signal when to stop packet capturing.
    """
    stop_event.set()