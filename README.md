Sharky is my first attempt at creating some public code It is a tool to either:

Read IPv4 packets from a network interface.
Its not meant to be a replace for a Wireshark/Tshark, its just provides a snapshot of the top talkers on a network

Its uses Streamlit for the Web frontend and scapy to read interface packets

-----------------
Setup & Install:

- Clone the repository

- pip install -r requirements

-----------------

Run:

- streamlit run main.py

-----------------

Options:

- Choose the interface to read from then start the capture

- Select the protocol types to ALL, TCP or UDP

- Initial view is limited to 20 lines, this can be increased as necessary

- Stop capture allows a download of the captured packets

-------------------

Notes:

- It works best when the capturing interface is attached to a mirror port on a switch
- If main.py is run under a non-root user then use setcap to allow python to read packets, this is a privileged operation. For example, "sudo setcap cap_net_raw=eip /usr/bin/pythonX.X". Please note there are security implications in doing this
