
from scapy.all import sniff
from scapy.layers.inet import IP, TCP
from datetime import datetime

captured_packets = []

def process_packet(packet):

    if packet.haslayer(IP):

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        protocol_num = packet[IP].proto

        protocol_map = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }

        protocol = protocol_map.get(protocol_num, str(protocol_num))

        packet_length = len(packet)

        timestamp = datetime.now().strftime("%H:%M:%S")

        # Default Threat
        threat = "Safe"

        # Simulated High-Risk Detection
        if packet_length > 200:
            threat = "High Risk"

        # TCP Port-Based Detection
        if packet.haslayer(TCP):

            dport = packet[TCP].dport

            if dport == 23:
                threat = "Medium Risk (Telnet)"

            elif dport == 445:
                threat = "High Risk (SMB)"

            elif dport == 21:
                threat = "Medium Risk (FTP)"

            elif dport == 3389:
                threat = "High Risk (RDP)"

        packet_info = {
            "Time": timestamp,
            "Source IP": src_ip,
            "Destination IP": dst_ip,
            "Protocol": protocol,
            "Packet Length": packet_length,
            "Threat Level": threat
        }

        captured_packets.append(packet_info)

def start_sniffing():

    sniff(
        prn=process_packet,
        store=False,
        timeout=10
    )

if __name__ == "__main__":
    start_sniffing()