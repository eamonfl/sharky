import streamlit as st
from PIL import Image, ImageOps
from capture_routines import start_capture, stop_capture
from display_function import update_and_display_packets
import scapy.all as scapy
import threading
from collections import defaultdict
from pathlib import Path  # Use pathlib for cleaner path handling

# Global Variables
packet_dict = defaultdict(int)
stop_event = threading.Event()

def initialize_session_state():
    """
    Initializes Streamlit session state variables with default values.
    """
    st.session_state.setdefault('is_capturing', False)
    st.session_state.setdefault('filter_ip', "")
    st.session_state.setdefault('filter_proto', "TCP & UDP")
    st.session_state.setdefault('num_entries', 20)
    st.session_state.setdefault('df', None)

def setup_page_config():
    """
    Configures Streamlit page settings, including checking for favicon existence.
    """
    favicon_path = Path("images/favicon-16x16.png")

    st.set_page_config(
        page_title="Network Packet Capture",
        page_icon=favicon_path if favicon_path.is_file() else None,
        layout="wide"  # Set layout to wide mode
    )

def display_header():
    """
    Displays the app header with an image and title.
    """
    col1, col2 = st.columns([1, 3])  # Adjust the ratio as needed

    # Load and display the shark image with error handling
    with col1:
        try:
            image = Image.open("images/sharky.jpg")
            bordered_image = ImageOps.expand(image.resize((150, 150)), border=10, fill='lightblue')
            st.image(bordered_image, caption="Sharky", use_container_width=False)
        except Exception as e:
            st.error("Failed to load the image.")

    # Display the title in the second column
    with col2:
        st.title("Network Packet Capture")

def setup_sidebar(interfaces):
    """
    Sets up the sidebar controls.
    """
    st.sidebar.title("Controls")
    iface = st.sidebar.selectbox("Select Network Interface", interfaces)

    if st.sidebar.button("Start Capturing") and not st.session_state.is_capturing:
        st.session_state.is_capturing = True
        try:
            start_capture(iface, packet_dict, stop_event)
        except Exception as e:
            st.error("Failed to start packet capture.")

    if st.sidebar.button("Stop Capturing"):
        stop_capture(stop_event)
        st.session_state.is_capturing = False

    st.session_state.filter_ip = st.sidebar.text_input("Filter by IP Address", st.session_state.filter_ip)
    st.session_state.filter_proto = st.sidebar.selectbox("Filter by Protocol", ["TCP & UDP", "TCP", "UDP"])
    st.session_state.num_entries = st.sidebar.selectbox("Number of Entries", [20, 50, 100, 200])

    return iface

def display_results():
    """
    Displays the results, including packet statistics and filtered data.
    """
    total_count_placeholder = st.empty()
    table_placeholder = st.empty()
    chart_placeholder = st.sidebar.empty()

    try:
        update_and_display_packets(packet_dict, table_placeholder, chart_placeholder, total_count_placeholder)
    except Exception as e:
        st.error("Failed to update display.")

def main():
    """
    Main entry point for the Streamlit app.
    """
    initialize_session_state()
    setup_page_config()
    display_header()

    # Fetch available interfaces with error handling
    try:
        interfaces = [iface for iface in scapy.get_if_list() if iface != "lo"]
        if not interfaces:
            st.sidebar.error("No network interfaces detected.")
            return
    except Exception as e:
        st.sidebar.error("Failed to fetch network interfaces.")
        return

    setup_sidebar(interfaces)
    display_results()

if __name__ == "__main__":
    main()