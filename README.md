# 🕵️‍♀️ Basic Network Sniffer using Python

This project is Task 1 of my Cyber Security Internship at **CodeAlpha**.  
It involves building a **Basic Network Sniffer** using Python and the `scapy` library.

---

## 📌 Project Description

A **network sniffer** is a tool that monitors and captures data packets flowing through a network.  
This simple Python script captures incoming and outgoing IP packets on the system and displays:

- Source IP Address
- Destination IP Address
- Protocol (TCP/UDP)

---

## ⚙️ How It Works

The script uses the **Scapy** library to:
- Capture network packets in real-time
- Filter only IP packets
- Extract essential information from each packet
- Print it to the terminal

---

## 🛠 Technologies Used

- Python 3.x
- Scapy (packet manipulation library)

---

## ▶️ How to Run

### 1. Install Scapy  
Open command prompt and run:
pip install scapy

### 2. Save the Script  
Save the following code in a file named `task1_sniffer.py`:

```python
from scapy.all import sniff, IP

def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print("\nNew Packet Captured")
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

# Start sniffing packets (use Ctrl+C to stop)
sniff(prn=process_packet, store=False)

### 3. Run the Script with Admin Privileges  
You must run it in terminal/Powershell **as Administrator**:
python task1_sniffer.py
