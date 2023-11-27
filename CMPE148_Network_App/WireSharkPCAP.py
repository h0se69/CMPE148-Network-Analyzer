import socket
from scapy.all import *
from scapy.all import IP, TCP, UDP, DNS, DNSQR
import json

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
# def get_packet_sizes(packets):
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