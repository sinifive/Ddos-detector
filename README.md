
# Network Packet Monitor

A GUI-based application for real-time Ethernet packet monitoring and DoS (Denial of Service) attack detection, built with Python (Tkinter) and Scapy.

## ✨ Features

- 📡 **Real-time packet capture** with detailed listing
- 🔎 **Detailed packet inspection**, including IP, TCP, and UDP fields
- ⚠️ **DoS attack detection** based on a configurable packet threshold
- 🛡️ **Auto-detection and exclusion of gateways** (e.g., router IPs)
- 🗂️ **Manage excluded IPs** interactively
- 🖥️ User-friendly **Tkinter-based GUI**

## 🖼️ Screenshots

> *(Add screenshots here if you'd like, e.g., main window, details panel, DoS alert popup)*

## ⚙️ Requirements

- Python 3.x
- [Scapy](https://scapy.net/) (`pip install scapy`)

> 💡 **Note**: You might need administrator/root privileges to capture packets depending on your OS.

## 🚀 How to Run

```bash
pip install scapy
python app.py

💡 Usage
Click Start to begin capturing packets.

View packets in the list; select any to see details.

Use the Threshold field to set your packets-per-second alert threshold for DoS detection.

When a possible DoS attack is detected, the app alerts you and offers to add the source IP to an exclusion list.

Manage excluded IPs from Settings > Manage Excluded IPs.

Click Stop to stop capturing.

⚠️ Notes
By default, the app excludes detected gateway IPs to reduce false alarms.

Auto-detection of gateway IPs is done after a sufficient number of packets have been captured.

You can manually add or remove IPs in the exclusion list.

📄 File Structure

app.py   # Main application code
README.md

🙏 Credits
Built using Tkinter for GUI and Scapy for packet capture.

Developed to provide an intuitive, beginner-friendly tool for network packet monitoring and security demonstration.

Feel free to fork, modify, and contribute!
