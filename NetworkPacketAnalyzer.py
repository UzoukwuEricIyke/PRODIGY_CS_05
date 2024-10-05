import threading
import time
from scapy.all import sniff, TCP, UDP, IP, ICMP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS, DNSQR
import logging
import json
import csv
from collections import defaultdict
import geoip2.database
from matplotlib import pyplot as plt
import networkx as nx

# Configure logging
logging.basicConfig(filename='packet_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

# Geolocation setup (requires geoip2 database)
reader = geoip2.database.Reader(
    'C:/Users/uzouk/OneDrive/Desktop/Nettwork Packet Analyzer/GeoLite2-City.mmdb')  # Ensure you download this database file

# Session tracking dictionary
sessions = defaultdict(list)

# Protocol count summary
protocol_count = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'HTTP': 0, 'DNS': 0, 'Encrypted': 0}

# Network mapping (graph for IP relationships)
network_graph = nx.Graph()

# Anomaly detection rules
anomalies = []

# List to store packets for export
packet_list = []


def detect_anomalies(packet):
    # Basic anomaly detection (e.g., too many packets from the same IP in a short time = possible DDoS)
    if IP in packet:
        src_ip = packet[IP].src
        # Track number of packets from each source IP
        if src_ip in sessions and len(sessions[src_ip]) > 100:  # Adjust the threshold based on your network
            anomalies.append(f"Potential anomaly: {src_ip} sent over 100 packets in a short time")
            print(f"Anomaly detected: {src_ip}")
            logging.info(f"Anomaly detected: {src_ip}")


def get_geo_info(ip_address):
    """Get geolocation info for an IP address"""
    try:
        response = reader.city(ip_address)
        return {
            "city": response.city.name,
            "country": response.country.name,
            "latitude": response.location.latitude,
            "longitude": response.location.longitude
        }
    except Exception as e:
        return None


def plot_network_graph():
    """Visualize the network graph using matplotlib and networkx"""
    pos = nx.spring_layout(network_graph)
    nx.draw(network_graph, pos, with_labels=True, node_size=500, node_color='lightblue', font_size=8)
    plt.savefig('network_map.png')
    plt.show()


def is_encrypted(packet):
    """Check if the packet is encrypted (e.g., part of HTTPS or TLS)"""
    if TCP in packet and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
        protocol_count['Encrypted'] += 1
        return True
    return False


def export_to_csv(data, filename='packet_data.csv'):
    """Export data to CSV format"""
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Source IP', 'Destination IP', 'Protocol', 'Payload'])
        for row in data:
            writer.writerow(row)


def export_to_json(data, filename='packet_data.json'):
    """Export data to JSON format"""
    with open(filename, 'w') as file:
        json.dump(data, file)


# Multi-threading support for packet sniffing
def packet_sniffing_thread(filter_str, duration, packet_limit):
    """Run the packet sniffing in a separate thread with dynamic duration and packet limit"""
    print(f"Starting packet sniffing for {duration} seconds, up to {packet_limit} packets...")
    sniff(filter=filter_str, prn=packet_callback, store=0, timeout=duration, count=packet_limit)
    print("Packet sniffing completed.")
    logging.info(f"Packet sniffing completed after {duration} seconds or {packet_limit} packets")


# Callback function to process each packet
def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = "Unknown"
        payload = None

        # Determine protocol and track sessions
        if TCP in packet:
            protocol = "TCP"
            protocol_count['TCP'] += 1
            payload = bytes(packet[TCP].payload)
            session_key = (src_ip, dst_ip, packet[TCP].sport, packet[TCP].dport)
        elif UDP in packet:
            protocol = "UDP"
            protocol_count['UDP'] += 1
            payload = bytes(packet[UDP].payload)
            session_key = (src_ip, dst_ip, packet[UDP].sport, packet[UDP].dport)
        elif ICMP in packet:
            protocol = "ICMP"
            protocol_count['ICMP'] += 1
            session_key = (src_ip, dst_ip)

        # Append packet to session
        sessions[session_key].append(packet)

        # Encryption detection
        if is_encrypted(packet):
            protocol = "Encrypted"
            print(f"Encrypted traffic detected from {src_ip} to {dst_ip}")
            logging.info(f"Encrypted traffic detected from {src_ip} to {dst_ip}")

        # Log and print basic packet info
        log_message = f"Packet: {src_ip} -> {dst_ip} | Protocol: {protocol}"
        logging.info(log_message)
        print(log_message)

        # Geolocation for source and destination
        src_geo = get_geo_info(src_ip)
        dst_geo = get_geo_info(dst_ip)
        if src_geo and dst_geo:
            logging.info(
                f"Source: {src_geo['city']}, {src_geo['country']} | Destination: {dst_geo['city']}, {dst_geo['country']}")
            network_graph.add_edge(src_ip, dst_ip)

        # HTTP Packet Analysis
        if packet.haslayer(HTTPRequest):
            protocol = "HTTP"
            protocol_count['HTTP'] += 1
            http_layer = packet[HTTPRequest]
            print(f"HTTP Request: {http_layer.Host}{http_layer.Path}")

        # DNS Packet Analysis
        elif packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
            protocol = "DNS"
            protocol_count['DNS'] += 1
            query_name = packet[DNSQR].qname.decode('utf-8')
            print(f"DNS Query: {query_name}")

        # Anomaly detection
        detect_anomalies(packet)

        # Track packet details for exporting
        packet_data = [src_ip, dst_ip, protocol, str(payload)]
        packet_list.append(packet_data)


# Packet capture function with dynamic duration and size limit
def start_packet_capture(filter_str="ip", duration=60, packet_limit=1000):
    """Start packet capture with dynamic duration and size limitation"""
    # Multi-threaded sniffing
    sniff_thread = threading.Thread(target=packet_sniffing_thread, args=(filter_str, duration, packet_limit))
    sniff_thread.start()
    sniff_thread.join()

    # After sniffing is done
    print(f"Protocol Summary: {protocol_count}")
    logging.info(f"Protocol Summary: {protocol_count}")

    # Export collected data
    export_to_csv(packet_list)
    export_to_json(packet_list)

    # Plot network graph
    plot_network_graph()


# Example usage
if __name__ == "__main__":
    # Example: Capture packets for 30 seconds, with a limit of 500 packets
    start_packet_capture(filter_str="ip", duration=30, packet_limit=500)
