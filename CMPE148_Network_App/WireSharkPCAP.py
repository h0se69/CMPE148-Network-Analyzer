import socket
from scapy.all import *
from scapy.all import IP, TCP, UDP, DNS, DNSQR
import json
import matplotlib
# matplotlib.use('Agg')
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
from datetime import datetime

socket.setdefaulttimeout(5) 

tcp_services = {
    "HTTP": 80,
    "HTTPS": 443,
    "FTP": 21,
    "SSH": 22,
    "Telnet": 23,
    "SMTP": 25,
    "DNS": 53,
    "POP3": 110,
    "IMAP": 143,
    "HTTPS (Secure SMTP)": 465,
    "HTTP2": 8080,
    "MySQL": 3306,
    "RDP": 3389,
}

udp_services = {
    "DNS": 53,
    "DHCP": 67,
    "DHCP (Client)": 68,
    "TFTP": 69,
    "SNMP": 161,
}

def check_for_IP(packet):
    if IP in packet:
        ip_layer = packet[IP]
        return ip_layer
    else:
        return False

def check_for_DNS(packet):
    if DNS in packet and packet.haslayer(DNSQR):
        dns_packet = packet[DNS]    
        return dns_packet
    else:
        return False


def get_DNS_host_name(ip_address):
    try:
        host_response = socket.gethostbyaddr(ip_address)
        host_name = host_response[0]
        return host_name
    except:
        return "Host not found / timed out"

def get_list_of_ips(packets):
    source_counter = {}
    destination_counter = {}
    source_to_destination_counter = {}

    for packet in packets:
        is_valid_IP = check_for_IP(packet)
        
        if is_valid_IP:
            ip_layer = is_valid_IP
            source_ip = get_IP_source_ip(ip_layer)
            destination_ip = get_IP_destination_ip(ip_layer)

            if(source_ip not in source_counter):
                source_counter[source_ip] = 1
            else:
                source_counter[source_ip] += 1

            if(destination_ip not in destination_counter):
                destination_counter[destination_ip] = 1
            else:
                destination_counter[destination_ip] += 1

            source_ip_to_desinttion_ip = f"{source_ip} > {destination_ip}"

            if(source_ip_to_desinttion_ip not in source_to_destination_counter):
                source_to_destination_counter[source_ip_to_desinttion_ip] = 1
            else:
                source_to_destination_counter[source_ip_to_desinttion_ip] += 1

    return_data = {
        "source_ips": sort_by_highest_frequency(source_counter), 
        "destination_ips": sort_by_highest_frequency(destination_counter), 
        "source_destination_ips": sort_by_highest_frequency(source_to_destination_counter)
    }
    return return_data


def sort_by_highest_frequency(dict_of_values:dict):
    return dict(sorted(dict_of_values.items(), key=lambda count: count[1], reverse=True))

def check_for_UDP(packet):
    if UDP in packet:
        udp_layer = packet[UDP]
        return udp_layer
    else: 
        return False

def check_for_TCP(packet):
    if TCP in packet:
        tcp_layer = packet[TCP]
        return tcp_layer
    else: 
        return False

def read_pcap_file(pcap_file_path):
    packets = rdpcap(pcap_file_path)
    return packets


# def check_all_packet_data(packets):
#     for packet in packets:
#         is_valid_TCP = check_for_TCP(is_valid_UDP)
#         is_valid_UDP = check_for_UDP(is_valid_UDP)

# def get_tcp_data(tcp_packet):
#     pass


# def get_total_packet_count(packets):
#     return len(packets)

# 
# IP
# 
def get_IP_source_ip(IP_Packet):
    return IP_Packet.src

def get_IP_destination_ip(IP_Packet):
    return IP_Packet.dst


def strip_packet_layer_name(layer):
    layer = str(layer)
    try:
        layer_name = layer.split(".")
        layer_name = layer_name[-1]
        layer_name = layer_name.split("'")
        layer_name = layer_name[0]
        return layer_name
    except:
        return layer

#
# Packet Data
#
def get_packet_sizes(packets, page, packets_per_page=200):

    total_packets = len(packets)
    total_pages = (total_packets + packets_per_page - 1) // packets_per_page 


    start_idx = (page - 1) * packets_per_page
    end_idx = start_idx + packets_per_page
    packets_on_page = packets[start_idx:end_idx]

    packet_list = []

    for id, packet in enumerate(packets_on_page):
        packet_size = len(packet)
        
        source_ip = packet[IP].src if packet.haslayer(IP) else None
        destination_ip = packet[IP].dst if packet.haslayer(IP) else None

        packet_info = {
                    "index": f"{start_idx + id + 1}",
                    "size": packet_size,
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                }
        packet_list.append(packet_info)
    
    return packet_list, total_pages


def calculate_total_data_transferred(packets):
    total_data = 0
    for packet in packets:
        if IP in packet:
            total_data += len(packet)
    return total_data

def prepare_flow_analysis_chart(packets):
    flows = {}
    start_time = packets[0].time if packets else 0

    for packet in packets:
        if IP in packet:
            source_ip_mac = get_IP_source_ip(packet)
            destination_ip_mac = get_IP_destination_ip(packet)
            source_ip = mac_to_ip4(source_ip_mac)
            destination_ip = mac_to_ip4(destination_ip_mac)

            flow_key = f"{source_ip} > {destination_ip}"

            if flow_key not in flows:
                flows[flow_key] = {'time_labels': [], 'traffic_values': []}

            relative_time = packet.time - start_time
            flows[flow_key]['time_labels'].append(relative_time)
            flows[flow_key]['traffic_values'].append(len(packet))
    return flows


def get_most_common_ip(flows, ip_type):
    ip_counter = {}

    for flow_key, flow_data in flows.items():
        ip = flow_key.split(' > ')[0] if ip_type == 'source' else flow_key.split(' > ')[1]
        if ip not in ip_counter:
            ip_counter[ip] = 1
        else:
            ip_counter[ip] += 1
    most_common_ip = max(ip_counter, key=ip_counter.get, default="No IPs found")
    return most_common_ip

def perform_flow_analysis(packets):
    flows = prepare_flow_analysis_chart(packets)
    return {
        'total_flows': len(flows),
        'most_common_source_ip': get_most_common_ip(flows, 'source'),
        'most_common_destination_ip': get_most_common_ip(flows, 'destination'),
        'flow_chart_data': flows,
    }
 

def mac_to_ip4(mac):
    bytes_list = [int(byte, 16) for byte in mac.split(':')[-6:]]
    ipv4_address = ".".join(map(str, bytes_list[-4:]))
    return ipv4_address

def calculate_bandwidth(packets, ip_address):
    total_bytes = 0
    start_time = None
    end_time = None

    for packet in packets:
        if IP in packet:
            source_ip = get_IP_source_ip(packet)
            destination_ip = get_IP_destination_ip(packet)
            packet_size = len(packet)

            if ip_address == source_ip or ip_address == destination_ip:
                total_bytes += packet_size

                # Update start_time and end_time
                if start_time is None or packet.time < start_time:
                    start_time = packet.time
                if end_time is None or packet.time > end_time:
                    end_time = packet.time

    if start_time is not None and end_time is not None:
        duration = end_time - start_time
        if duration > 0:
            # Calculate average bandwidth (bytes per second)
            average_bandwidth_bps = total_bytes / duration

            # Convert to megabits per second (Mbps)
            average_bandwidth_mbps = average_bandwidth_bps * 8 / 1_000_000
            return average_bandwidth_mbps

    return 0

# def get_bandwidth_info(packets):
#     bandwidth_info = {}

#     for packet in packets:
#         if IP in packet:
#             source_ip = packet[IP].src
#             destination_ip = packet[IP].dst
#             packet_size = len(packet)

#             # Process source IP
#             if source_ip not in bandwidth_info:
#                 bandwidth_info[source_ip] = 0

#             bandwidth_info[source_ip] += packet_size

#             # Process destination IP
#             if destination_ip not in bandwidth_info:
#                 bandwidth_info[destination_ip] = 0

#             bandwidth_info[destination_ip] += packet_size

#     return bandwidth_info

def get_bandwidth_info(packets):
    bandwidth_info = {}

    for packet in packets:
        if IP in packet:
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
            packet_size = len(packet)

            # Process source IP
            if source_ip not in bandwidth_info:
                bandwidth_info[source_ip] = {'total_bandwidth': 0, 'mbps': 0}

            bandwidth_info[source_ip]['total_bandwidth'] += packet_size

            # Process destination IP
            if destination_ip not in bandwidth_info:
                bandwidth_info[destination_ip] = {'total_bandwidth': 0, 'mbps': 0}

            bandwidth_info[destination_ip]['total_bandwidth'] += packet_size

    # Calculate Mbps
    for ip, data in bandwidth_info.items():
        total_bandwidth_bytes = data['total_bandwidth']
        total_bandwidth_mbps = total_bandwidth_bytes * 8 / 1_000_000
        bandwidth_info[ip]['mbps'] = total_bandwidth_mbps

    return bandwidth_info