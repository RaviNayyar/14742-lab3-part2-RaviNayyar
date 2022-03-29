#!/usr/bin/env python3

from curses import raw
import socket, sys, time, struct

ETH_P_ALL = 0x0003


def set_up_listener():
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    except socket.error as msg:
        print('error ' + str(msg[0]) + ': ' + msg[1])
        sys.exit() 
    return sock


def convert_string_to_mac(mac_bytes):
    mac_bytes = mac_bytes.hex()
    mac = ""
    for i in range(0,12,2):
        mac += "{}{}:".format(mac_bytes[i], mac_bytes[i+1])   

    return mac[:-1]


def convert_string_to_ip(ip_bytes):
    ip = ""
    for i in range(0,8,2):
        ip += "{}.".format(int("0x{}{}".format(ip_bytes[i], ip_bytes[i+1]), 16))
    
    ip = ip[:-1]
    return ip


def ipv6_packet():
    print("IPv6 Packet")


def icmp_packet(icmp_pkt):
    type = icmp_pkt[0:1].hex()
    if type == "08":
        type = "ICMP ECHO Request"
    elif type == "00":
        type = "ICMP ECHO Reply"
    print(type)


def arp_packet(raw_data):
    proto_type = convert_protocol(int("0x"+raw_data[2:4].hex(), 16))
    opcode = raw_data[6:8].hex()

    print("Protocol: ", proto_type)
    print("Sender  IP: {} ==> Destination  IP: {}".format(convert_string_to_ip(raw_data[14:18].hex()), convert_string_to_ip(raw_data[24:].hex())))
    print("Sender MAC: {} ==> Destination MAC: {}".format(convert_string_to_mac(raw_data[8:14]), convert_string_to_mac(raw_data[18:24])))

    if opcode == "0001":
        print("ARP Request")
    elif opcode == "0002":
        print("ARP Reply")


def udp_packet(raw_data):
    print("\nUDP Packet")
    data = raw_data.hex()

    source_port = raw_data[0:2].hex()
    dest_port = raw_data[2:4].hex()
    print("Source Port: {} Dest Port: {}".format(int(source_port,16), int(dest_port,16)))


def tcp_packet(raw_data):
    flags = raw_data[13:14].hex()
    if flags == "02":
        print("TCP SYN Packet")
    elif flags == "12":
        print("TCP SYN ACK Packet")


'''
Citation: https://en.wikipedia.org/wiki/Ethernet_frame
'''
def convert_protocol(protocol):
    if protocol == 2048:
        return "IPv4"
    elif protocol == 2054:
        return "ARP"
    elif protocol == 34525:
        return "IPv6"
    elif protocol == 33024:
        return "IEEE_802.1Q_tag"


def ipv4_head(raw_data):
    len_and_ver = raw_data[0:1].hex()
    type_of_service = raw_data[1:2].hex()
    packet_length = raw_data[2:4].hex()  
    packet_id = raw_data[4:6].hex()
    frag_flags_and_offset = raw_data[6:8].hex()
    ttl = raw_data[8:9].hex()
    proto_id = raw_data[9:10].hex()
    cksm = raw_data[10:12].hex()
    src_ip = convert_string_to_ip(raw_data[12:16].hex())
    dst_ip = convert_string_to_ip(raw_data[16:20].hex())
    
    print("Src IP: {} ==> Dest IP {}".format(src_ip, dst_ip))
    print("len_and_ver: {}  type_of_service: {}".format(len_and_ver, type_of_service))
    print("pkt_len: {}  pkt_id: {}   flags: {}".format(packet_length, packet_id, frag_flags_and_offset))
    print("ttl: {}   proto_id: {}   cksm: {}".format(ttl, proto_id, cksm))


    return proto_id


def ethernet_head(raw_data):
    dest, src, ether_type = struct.unpack('!6s6sH', raw_data)
    destination_mac = convert_string_to_mac(dest)
    source_mac = convert_string_to_mac(src)
    proto = convert_protocol(ether_type)
    print("Src Mac: {} ==> Dest Mac {} | Proto: {}".format(source_mac, destination_mac, proto))
    return proto


def unpack_packet(pkt):
    byte_str = pkt[0]

    print("_"*70)

    proto = ethernet_head(byte_str[:14])
    if proto == "IPv4":
        # Comparator values are hex strings
        id = ipv4_head(byte_str[14:34])
        if id == "01": # ICMP Packet
            icmp_packet(byte_str[34:])
        elif id == "06": #TCP Packet
            tcp_packet(byte_str[34:])
        elif id == "11": #UDP Packet
            udp_packet(byte_str[34:])
    elif proto == "ARP":
        arp_packet(byte_str[14:])
    elif proto == "IPv6":
        ipv6_packet()


    print("_"*70)


if __name__ == "__main__":

    sock = set_up_listener()
    
    while(1):
        pkt = sock.recvfrom(0xffff)
        unpack_packet(pkt) 
    
    sock.close()
