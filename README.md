This project was developed as part of my work at Prodigy InfoTech for my Cybersecurity Internship.

This project is a Python-based **Network Packet Analyzer** that captures and analyzes network traffic using advanced features like session tracking, protocol analysis, geolocation, encryption detection, and anomaly detection. The analyzer is multi-threaded for efficiency, supports dynamic packet capture durations, and limits the capture size to avoid memory overload. It also provides visualization, exports packet data in multiple formats, and supports tracking of various protocols, including HTTP, DNS, and more.

## Features

- **Multi-Threading for Efficiency**: Packet sniffing runs in a separate thread, allowing for more efficient operation.
- **Dynamic Packet Sniffing Duration**: The duration of packet capture can be set dynamically.
- **Packet Capture Size Limitation**: Specify a limit for the number of packets captured to prevent memory overload.
- **Advanced Protocol Support**: The analyzer supports multiple protocols such as TCP, UDP, ICMP, HTTP, DNS, and detection of encrypted traffic (e.g., HTTPS).
- **Session Tracking**: Tracks sessions between source and destination IPs for protocols like TCP and UDP.
- **Geolocation of IP Addresses**: Uses the GeoLite2 database to determine the geolocation of IP addresses.
- **Encryption Detection**: Detects encrypted traffic (e.g., HTTPS).
- **Anomaly Detection**: Basic anomaly detection, such as identifying potential DDoS attacks based on packet counts.
- **Data Export**: Exports captured data in CSV and JSON formats.
- **Network Mapping**: Visualizes the network structure by creating a graph of relationships between IPs.
- **Protocol Count Summary**: Summarizes the number of packets captured per protocol.
  
## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/UzoukwuEricIyke/PRODIGY_CS_05.git
    cd PRODIGY_CS_05
    ```

2.Set Up a Virtual Environment (Optional):
python -m venv .venv
source .venv/bin/activate  # On Windows use `.venv\Scripts\activate`

3.  Install the required dependencies:
    ```bash
    pip install scapy geoip2 networkx matplotlib
    ```

4. Download the GeoLite2-City database from MaxMind:
    - [GeoLite2 Free Geolocation Data](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
    - Place the `GeoLite2-City.mmdb` file in the same directory as `NetworkPacketAnalyzer.py`.

## Usage

To start the network packet analyzer:

1. Run the `NetworkPacketAnalyzer.py` file:
    ```bash
    python NetworkPacketAnalyzer.py
    ```

2. You can configure the packet capture parameters (e.g., duration, packet limit) inside the script:
    ```python
    start_packet_capture(filter_str="ip", duration=30, packet_limit=500)
    ```

### Example:
This command will capture packets for 30 seconds with a limit of 500 packets.

## Visualizing the Network

After packet capture, a network map is generated and saved as an image (`network_map.png`). This visualizes the relationships between source and destination IPs.

## View Logs and Exported Data:

Captured packet data is exported into two formats:
- Logs are stored in `packet_log.txt`.
- Exported packet data can be found in `packet_data.csv` and `packet_data.json`.

## Contributions

Contributions to improve this project are welcome! Feel free to submit issues or pull requests to enhance the functionality.

## Contact
For questions or suggestions, please contact Uzoukwu Eric Ikenna
## Email
uzoukwuericiyke@yahoo.com
## LinkedIn
https://www.linkedin.com/in/uzoukwu-eric-ikenna/
