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


# def get_DNS_host_name(packet):
#     is_valid_DNS = check_for_DNS(packet)
#     if is_valid_DNS:
#         dns_packet = is_valid_DNS
#         try:
#             host_name = dns_packet.qd.qname.decode("utf-8")
#         except:
#             host_name = "N/A Error"
#     else:
#         return False

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



# def get_all_protocols(packets):
    # protocols = set()

    # for packet in packets:
    #     for layer in packet.layers():
    #         layer_name = strip_packet_layer_name(layer)
    #         protocols.add(layer_name)
    # return protocols

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


# packets = read_pcap_file("web_get.pcap")
# number_of_address_connections = get_list_of_ips(packets)

# for source_ip in number_of_address_connections["source_ips"]:
#     print(get_DNS_host_name(source_ip))

# print(json.dumps(number_of_address_connections, indent=4))
