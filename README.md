# Sharky
<p align="center">
  <img src="https://github.com/eamonfl/sharky/blob/master/images/sharky.jpg" width="350" title="hover text">
</p>

## Introduction
Sharky is a simple tool designed to capture and analyze IPv4 packets from a network interface. Unlike Wireshark or Tshark, Sharky is not a full-fledged network analysis tool. Instead, it provides a quick snapshot of the top talkers on a network in a lightweight, user-friendly interface.

Sharky uses Streamlit for its web-based frontend and Scapy for packet capture.

## Features
- Capture IPv4 packets from a selected network interface.
- View the top talkers in a real-time table format.
- Filter traffic by protocol (ALL, TCP, or UDP).
- Customize the number of displayed entries.
- Download captured packets for further analysis.

## Setup & Installation

- Clone the repository:
'''
git clone https://github.com/yourusername/sharky.git
cd sharky
'''
'''
pip install -r requirements
'''

## Usage
'''
streamlit run main.py
'''

ollow the on-screen instructions:

- Select Network Interface: Choose the interface you want to capture packets from.
- Start Capture: Begin capturing packets from the selected interface.
- Filter Options: Filter captured packets by protocol (ALL, TCP, or UDP).
- Adjust Entries: Initially, the view is limited to 20 lines, but you can increase this as needed.
- Stop Capture: End the capture session and download the captured packets for offline analysis.

## Notes

- Mirror Port Recommended: Sharky works best when the capturing interface is attached to a mirror (SPAN) port on a network switch.
- Permission Requirements: Capturing packets is a privileged operation. If you run main.py under a non-root user, you may need to grant your Python binary permission to capture packets:
'''
sudo setcap cap_net_raw=eip $(which python)
'''
⚠️ Security Implications: Using setcap can introduce security risks. Use with caution and only if necessary.
- Supported Environments: Tested on:
Ubuntu 24.10
Debian 12

## Contributing
Contributions are welcome! Feel free to open issues or submit pull requests to enhance Sharky.

## License
This project is licensed under the MIT License. Feel free to use, modify, and distribute it.

