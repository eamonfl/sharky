
# Sharky
<p align="center">
  <img src="https://github.com/eamonfl/sharky/blob/master/images/sharky.jpg" width="350" title="hover text">
</p>

## Introduction
Sharky is my first attempt at creating some public code It is a tool to read IPv4 packets from a network interface. 
It is not meant to be a replace for a Wireshark/Tshark, its just provides a snapshot of the top talkers on a network

Its uses Streamlit for the Web frontend and scapy to read interface packets

## Setup & Instal

- Clone the repository

- pip install -r requirements

## Run

- streamlit run main.py

## Options

- Choose the interface to read from then start the capture

- Select the protocol types to ALL, TCP or UDP

- Initial view is limited to 20 lines, this can be increased as necessary

- Stop capture allows a download of the captured packets

## Notes

- It works best when the capturing interface is attached to a mirror port on a switch
- If main.py is run under a non-root user then use setcap to allow python to read packets, this is a privileged operation. For example, "sudo setcap cap_net_raw=eip /usr/bin/pythonX.X". Please note there are security implications in doing this
- Tested on Ubuntu 24.10 and Debian 12
