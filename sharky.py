import scapy.all as scapy
import streamlit as st
import matplotlib.pyplot as plt
import pandas as pd
from scapy.layers.inet import IP, TCP, UDP
import threading
import time
from collections import defaultdict
from PIL import Image

# Function to capture packets
def capture_packets(packet_dict, stop_event, iface):
    def packet_callback(packet):
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            if TCP in packet:
                proto = "TCP"
                sport = packet[TCP].sport
                dport = packet[TCP].dport
            elif UDP in packet:
                proto = "UDP"
                sport = packet[UDP].sport
                dport = packet[UDP].dport
            else:
                proto = "Other"
                sport = dport = None

            connection = f"{ip_src}:{sport} -> {ip_dst}:{dport}"
            packet_dict[(connection, proto)] += 1

    scapy.sniff(prn=packet_callback, stop_filter=lambda x: stop_event.is_set(), store=False, iface=iface)

# Global packet dictionary and stop event
packet_dict = defaultdict(int)
stop_event = threading.Event()

# Function to start capturing packets
def start_capture(iface):
    packet_dict.clear()
    stop_event.clear()
    capture_thread = threading.Thread(target=capture_packets, args=(packet_dict, stop_event, iface))
    capture_thread.start()
    return capture_thread

# Function to stop capturing packets
def stop_capture():
    stop_event.set()

# Streamlit interface
st.set_page_config(page_title="Continuous Network Packet Capture", page_icon="images/favicon-16x16.png")

# Resize and display the logo image next to the title
image = Image.open("images/sharky.jpg")
width, height = image.size
new_size = (int(width * 0.5), int(height * 0.5))  # Resize to 50% smaller
resized_image = image.resize(new_size)

col1, col2 = st.columns([1, 3])
with col1:
    st.image(resized_image, caption="Sharky", width=150)  # Shrink image further
with col2:
    st.title("Continuous Network Packet Capture")

# Initialize session state
st.session_state.setdefault('is_capturing', False)
st.session_state.setdefault('packet_list', [])
st.session_state.setdefault('filter_ip', "")
st.session_state.setdefault('filter_proto', "TCP & UDP")
st.session_state.setdefault('num_entries', 20)

# Get list of network interfaces
interfaces = [iface for iface in scapy.get_if_list() if iface != "lo"]

# Sidebar controls
st.sidebar.title("Controls")
iface_select = st.sidebar.selectbox("Select Network Interface", interfaces)

if st.sidebar.button("Start Capturing"):
    if not st.session_state.is_capturing:
        st.session_state.is_capturing = True
        capture_thread = start_capture(iface_select)
        st.sidebar.text(f"Capturing started on {iface_select}...")

if st.sidebar.button("Stop Capturing"):
    stop_capture()
    st.session_state.is_capturing = False
    st.sidebar.text("Capturing stopped.")
    if 'capture_thread' in locals():
        capture_thread.join()

# Sidebar filters with automatic stop and restart on change
new_filter_ip = st.sidebar.text_input("Filter by IP Address", st.session_state.filter_ip)
new_filter_proto = st.sidebar.selectbox("Filter by Protocol", ["TCP & UDP", "TCP", "UDP"], index=["TCP & UDP", "TCP", "UDP"].index(st.session_state.filter_proto))
new_num_entries = st.sidebar.selectbox("Number of Entries to Display", [20, 50, 100, 200], index=[20, 50, 100, 200].index(st.session_state.num_entries))

if (new_filter_ip != st.session_state.filter_ip or new_filter_proto != st.session_state.filter_proto):
    # Stop the current capture
    if st.session_state.is_capturing:
        stop_capture()
        st.session_state.is_capturing = False

    # Update session state with new filters
    st.session_state.filter_ip = new_filter_ip
    st.session_state.filter_proto = new_filter_proto

    # Restart the capture automatically
    st.session_state.is_capturing = True
    capture_thread = start_capture(iface_select)

# Display placeholders
table_placeholder = st.empty()
chart_placeholder = st.sidebar.empty()

# Function to update and display the packet list
def update_and_display_packets():
    while st.session_state.is_capturing:
        total_packets = sum(packet_dict.values())
        packet_list = [
            {
                "Connection": connection,
                "Protocol": proto,
                "Count": count,
                "Percentage": f"{(count / total_packets) * 100:.2f}%"
            }
            for (connection, proto), count in packet_dict.items()
        ]

        # Apply filters
        filtered_list = packet_list
        if st.session_state.filter_ip:
            filtered_list = [pkt for pkt in filtered_list if st.session_state.filter_ip in pkt["Connection"]]
        if st.session_state.filter_proto != "TCP & UDP":
            filtered_list = [pkt for pkt in filtered_list if pkt["Protocol"] == st.session_state.filter_proto]

        if filtered_list:  # Check if there is any data to display
            top_packets = sorted(filtered_list, key=lambda x: x["Count"], reverse=True)[:st.session_state.num_entries]

            # Display as DataFrame
            df = pd.DataFrame(top_packets).reset_index(drop=True)  # Remove the index
            table_placeholder.dataframe(df, height=600, width=900)

            # Pie chart summary
            connection_counts = defaultdict(int)
            for pkt in filtered_list:
                connection_counts[pkt["Connection"]] += pkt["Count"]

            connections = list(connection_counts.keys())
            counts = list(connection_counts.values())

            # Group smaller slices as "Others"
            if len(connections) > 10:
                others_count = sum(counts[10:])
                connections = connections[:10] + ["Others"]
                counts = counts[:10] + [others_count]

            fig, ax = plt.subplots()
            ax.pie(counts, labels=connections, autopct='%1.1f%%', startangle=90)
            ax.axis('equal')

            chart_placeholder.pyplot(fig)
            plt.close(fig)
        else:
            table_placeholder.text("No matching data found.")  # Display a message if no data matches

        time.sleep(1)

if st.session_state.is_capturing:
    update_and_display_packets()
