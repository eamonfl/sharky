import os
import time
import threading
import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from PIL import Image, ImageOps
from collections import defaultdict
from capture_routines import start_capture, stop_capture, packet_dict_lock
from ipwhois import IPWhois
import scapy.all as scapy
from typing import Dict, Any, List, Tuple

# Global variables
packet_dict = defaultdict(int)
stop_event = threading.Event()

def initialize_session_state() -> None:
    """
    Initializes the session state with default values.
    """
    st.session_state.setdefault('is_capturing', False)
    st.session_state.setdefault('filter_ip', "")
    st.session_state.setdefault('filter_proto', "TCP & UDP")
    st.session_state.setdefault('num_entries', 20)
    st.session_state.setdefault('df', None)

def setup_page_config() -> None:
    """
    Configures the Streamlit page settings including title, icon, and layout.
    """
    page_title = os.getenv('PAGE_TITLE', 'Network Packet Capture')
    page_icon_path = os.getenv('PAGE_ICON', 'images/favicon-16x16.png')

    if not os.path.exists(page_icon_path):
        st.warning(f"Page icon file not found: {page_icon_path}")
        page_icon_path = None  # Use default icon if file is missing

    try:
        st.set_page_config(
            page_title=page_title,
            page_icon=page_icon_path,
            layout="wide"
        )
    except Exception as e:
        st.error(f"Failed to set page config: {e}")

def display_header() -> None:
    """
    Displays the header with an image and title.
    """
    col1, col2 = st.columns([1, 3])

    with col1:
        image = Image.open("images/sharky.jpg")
        bordered_image = ImageOps.expand(image.resize((150, 150)), border=10, fill='lightblue')
        st.image(bordered_image, caption="Sharky", use_container_width=False)

    with col2:
        st.title("Network Packet Capture")

def setup_sidebar(interfaces: List[str]) -> str:
    """
    Sets up the sidebar with controls for capturing packets.

    Args:
        interfaces (List[str]): List of network interfaces.

    Returns:
        str: Selected network interface.
    """
    st.sidebar.title("Controls")
    iface = st.sidebar.selectbox("Select Network Interface", interfaces)

    if st.sidebar.button("Start Capturing") and not st.session_state.is_capturing:
        st.session_state.is_capturing = True
        start_capture(iface, packet_dict, stop_event)

    if st.sidebar.button("Stop Capturing"):
        stop_capture(stop_event)
        st.session_state.is_capturing = False

    st.session_state.filter_ip = st.sidebar.text_input("Filter by IP Address", st.session_state.filter_ip)
    st.session_state.filter_proto = st.sidebar.selectbox("Filter by Protocol", ["TCP & UDP", "TCP", "UDP"])
    st.session_state.num_entries = st.sidebar.selectbox("Number of Entries", [20, 50, 100, 200])

    return iface

def get_country_from_ip(ip_address: str) -> str:
    """
    Retrieves the country associated with an IP address.

    Args:
        ip_address (str): IP address to lookup.

    Returns:
        str: Country code or 'Unknown' if not found.
    """
    try:
        obj = IPWhois(ip_address)
        result = obj.lookup_rdap()
        return result.get('network', {}).get('country', 'Unknown')
    except Exception:
        return 'Unknown'

def prepare_packet_data(packet_dict: Dict[str, int]) -> Tuple[pd.DataFrame, List[Dict[str, Any]], List[int]]:
    """
    Prepares packet data for display.

    Args:
        packet_dict (Dict[str, int]): Dictionary containing packet data.

    Returns:
        Tuple[pd.DataFrame, List[Dict[str, Any]], List[int]]: DataFrame of packet data, top connections, and counts.
    """
    total_packets = 0
    merged_connections = defaultdict(lambda: {"Count": 0, "Requests": 0, "Responses": 0, "Protocol": ""})

    with packet_dict_lock:
        total_packets = sum(packet_dict.values())
        for (connection, proto), count in packet_dict.items():
            ip_src, ip_dst = connection.split(" -> ")
            src_to_dst = f"{ip_src} <-> {ip_dst}"
            dst_to_src = f"{ip_dst} <-> {ip_src}"

            if dst_to_src in merged_connections:
                merged_connections[dst_to_src]["Count"] += count
                merged_connections[dst_to_src]["Responses"] += count
            else:
                merged_connections[src_to_dst]["Count"] += count
                merged_connections[src_to_dst]["Requests"] += count
                merged_connections[src_to_dst]["Protocol"] = proto

    packet_list = [
        {
            "Connection": connection,
            "Protocol": data["Protocol"],
            "Requests": data["Requests"],
            "Responses": data["Responses"],
            "Total Count": data["Count"],
            "Percentage": f"{(data['Count'] / total_packets) * 100:.2f}%",
            "Country": get_country_from_ip(connection.split(" <-> ")[1])
        }
        for connection, data in merged_connections.items()
    ]

    filtered_list = [
        pkt for pkt in packet_list
        if (not st.session_state.filter_ip or st.session_state.filter_ip in pkt["Connection"]) and
        (st.session_state.filter_proto == "TCP & UDP" or pkt["Protocol"] == st.session_state.filter_proto)
    ]

    sorted_packets = sorted(filtered_list, key=lambda x: x["Total Count"], reverse=True)
    df = pd.DataFrame(sorted_packets[:st.session_state.num_entries])

    return df, sorted_packets[:5], [pkt["Total Count"] for pkt in sorted_packets[:5]]

def display_packet_data(df: pd.DataFrame, connections: List[Dict[str, Any]], counts: List[int], table_placeholder, chart_placeholder) -> None:
    """
    Displays packet data in a table and pie chart.

    Args:
        df (pd.DataFrame): DataFrame of packet data.
        connections (List[Dict[str, Any]]): Top connections.
        counts (List[int]): Counts of top connections.
        table_placeholder: Streamlit placeholder for table.
        chart_placeholder: Streamlit placeholder for chart.
    """
    st.session_state.df = df

    def highlight_max(s):
        is_max = s == s.max()
        return ['background-color: yellow' if v else '' for v in is_max]

    df.reset_index(drop=True, inplace=True)
    styled_df = df.style.apply(highlight_max, subset=["Total Count"])
    table_placeholder.table(styled_df)

    fig, ax = plt.subplots(figsize=(8, 6))
    short_labels = [f"Conn {i+1}" for i in range(len(connections))]
    wedges, texts, autotexts = ax.pie(counts, labels=short_labels, autopct='%1.1f%%', startangle=90)

    ip_addresses = [conn['Connection'] for conn in connections]
    ax.legend(
        wedges,
        ip_addresses,
        title="IP Addresses",
        loc="lower center",
        bbox_to_anchor=(0.5, -0.3),
        ncol=1,
        fontsize='small'
    )

    ax.axis('equal')
    plt.tight_layout()
    chart_placeholder.pyplot(fig)
    plt.close(fig)

def update_and_display_packets(packet_dict: Dict[str, int], table_placeholder, chart_placeholder, total_count_placeholder) -> None:
    """
    Continuously updates and displays packet data.

    Args:
        packet_dict (Dict[str, int]): Dictionary containing packet data.
        table_placeholder: Streamlit placeholder for table.
        chart_placeholder: Streamlit placeholder for chart.
        total_count_placeholder: Streamlit placeholder for total count.
    """
    while st.session_state.is_capturing:
        df, connections, counts = prepare_packet_data(packet_dict)

        if not df.empty:
            total_count = df["Total Count"].sum()
            total_count_placeholder.markdown(
                f"<h4 style='color:gray;'>Total Packets Processed: {total_count:,}</h4>", unsafe_allow_html=True
            )
            display_packet_data(df, connections, counts, table_placeholder, chart_placeholder)
        else:
            table_placeholder.text("No matching data found.")

        time.sleep(1)