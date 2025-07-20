from scapy.all import sniff, IP
import time

# Map protocol numbers to names (for common ones)
protocols = {1: "ICMP", 6: "TCP", 17: "UDP"}

def show_packet(packet):
    if IP in packet:
        proto_num = packet[IP].proto
        proto_name = protocols.get(proto_num, f"Other({proto_num})")
        
        print("\n📦 New Packet Captured")
        print("🕒 Time:", time.strftime("%Y-%m-%d %H:%M:%S"))
        print("📍 Source IP:", packet[IP].src)
        print("🎯 Destination IP:", packet[IP].dst)
        print("📡 Protocol:", proto_name)
        print("📏 Packet Size:", len(packet), "bytes")
        print("-" * 40)

# Start sniffing 5 packets
print("🚀 Sniffing started. Waiting for packets...\n")
sniff(prn=show_packet, count=5)
print("\n✅ Sniffing complete.")
