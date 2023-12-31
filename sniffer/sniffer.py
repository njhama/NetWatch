import pyshark
import geoip2.database
from datetime import datetime
import time
import queue
import logging

packet_log = logging.getLogger('packet_logger')
packet_log.setLevel(logging.INFO)
packet_formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s')
packet_handler = logging.FileHandler('packet_sniffer.log')
packet_handler.setFormatter(packet_formatter)
packet_log.addHandler(packet_handler)
bandwidth_log = logging.getLogger('bandwidth_logger')
bandwidth_log.setLevel(logging.INFO)
bandwidth_formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s')
bandwidth_handler = logging.FileHandler('bandwidth.log')
bandwidth_handler.setFormatter(bandwidth_formatter)
bandwidth_log.addHandler(bandwidth_handler)

def ip_lookup(ip_addr, reader):
    try:
        response = reader.city(ip_addr)
        info_parts = []
        if response.city.name:
            info_parts.append(f"City: {response.city.name}")
        if response.subdivisions.most_specific.name:
            info_parts.append(f"Region: {response.subdivisions.most_specific.name}")
        if response.country.name:
            info_parts.append(f"Country: {response.country.name}")
        if response.postal.code:
            info_parts.append(f"Postal Code: {response.postal.code}")
        if response.location.latitude and response.location.longitude:
            info_parts.append(f"Coordinates: {response.location.latitude}, {response.location.longitude}")
        return ', '.join(info_parts) if info_parts else 'Location Info Not Available'
    except Exception:
        return 'Lookup Failed'
    
def run_sniffer(queue, interface='Ethernet', packet_count=1000):
    with geoip2.database.Reader('./data/GeoLite2-City.mmdb') as reader:
        capture = pyshark.LiveCapture(interface=interface)  
        total_bytes = 0
        start_time = time.time()
        for packet in capture.sniff_continuously(packet_count=packet_count):
            src_addr = packet.ip.src if 'IP' in packet else 'Unknown'
            dst_addr = packet.ip.dst if 'IP' in packet else 'Unknown'
            src_info = ip_lookup(src_addr, reader) if src_addr != 'Unknown' else 'Unknown'
            dst_info = ip_lookup(dst_addr, reader) if dst_addr != 'Unknown' else 'Unknown'
            packet_type = packet.highest_layer
            packet_length = int(packet.length)
            timestamp = datetime.fromtimestamp(float(packet.sniff_timestamp)).strftime('%Y-%m-%d %H:%M:%S')
            packet_info = f'{timestamp} | {src_addr} ({src_info}) -> {dst_addr} ({dst_info}) | Type: {packet_type} | Length: {packet_length}'
            queue.put(packet_info)
            packet_log.info(packet_info)
            total_bytes += packet_length
            current_time = time.time()
            if current_time - start_time >= 1:
                bandwidth = total_bytes / (current_time - start_time)  
                bandwidth_log_entry = f"Bandwidth: {bandwidth:.2f} bytes/sec"
                queue.put(bandwidth_log_entry)
                bandwidth_log.info(bandwidth_log_entry)
                total_bytes = 0
                start_time = current_time

