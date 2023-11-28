import socket
from scapy.all import *
from scapy.all import IP, TCP, UDP, DNS, DNSQR
import json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

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


def check_all_packet_data(packets):
    for packet in packets:
        is_valid_TCP = check_for_TCP(is_valid_UDP)
        is_valid_UDP = check_for_UDP(is_valid_UDP)

def get_tcp_data(tcp_packet):
    pass


def get_total_packet_count(packets):
    return len(packets)

# 
# IP
# 
def get_IP_source_ip(IP_Packet):
    return IP_Packet.src

def get_IP_destination_ip(IP_Packet):
    return IP_Packet.dst

def get_ip_protocol(IP_Packet):
    return IP_Packet.proto

# 
# UDP
# 

def get_UDP_source_port(UDP_Packet):
    return UDP_Packet.sport

def get_UDP_destination_port(UDP_Packet):
    return UDP_Packet.dport

def get_UDP_checksum(UDP_Packet):
    return UDP_Packet.checksum

# 
# TCP
# 
def get_TCP_source_port(TCP_Packet):
    return TCP_Packet.sport

def get_TCP_destination_port(TCP_Packet):
    return TCP_Packet.dport


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
def calculate_total_data_transferred(packets):
    total_data = 0
    for packet in packets:
        if IP in packet:
            total_data += len(packet)
    return total_data

def prepare_flow_analysis_chart(packets):
    flows = {}

    # Keep track of the starting time
    start_time = packets[0].time if packets else 0

    for packet in packets:
        if IP in packet:
            source_ip = get_IP_source_ip(packet)
            destination_ip = get_IP_destination_ip(packet)
            flow_key = f"{source_ip} > {destination_ip}"

            if flow_key not in flows:
                flows[flow_key] = {'time_labels': [], 'traffic_values': []}

            # Calculate relative time and traffic
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

def extract_flow_chart_data(flows):
    time_labels = []
    all_flow_values = []

    for flow_key, flow_data in flows.items():
        time_labels = flow_data['time_labels']
        flow_values = flow_data['traffic_values']
        all_flow_values.append(flow_values)

    # Find the maximum length among all flow values and truncate the others
    max_length = max(len(flow_values) for flow_values in all_flow_values)
    truncated_flow_values = [flow_values[:max_length] for flow_values in all_flow_values]

    # Calculate the average flow values at each time point
    averaged_flow_values = [sum(flow_values) / len(flow_values) for flow_values in zip(*truncated_flow_values)]

    return {
        'time_labels': time_labels,
        'flow_values': averaged_flow_values,
    }


def perform_flow_analysis(pcap_file_path):
    packets = rdpcap(pcap_file_path)
    flows = prepare_flow_analysis_chart(packets)
    flow_chart_data = extract_flow_chart_data(flows)
    print("flows:",flows)
    return {
        'total_flows': len(flows),
        'most_common_source_ip': get_most_common_ip(flows, 'source'),
        'most_common_destination_ip': get_most_common_ip(flows, 'destination'),
        'flow_chart_data': flow_chart_data,
    }
# 