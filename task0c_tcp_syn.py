#!/usr/bin/env python3

import socket, sys, time, struct, binascii, random
from tabnanny import check

def setup_connection():
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.bind(("eth0",0))

    except socket.error as msg:
        print('error ' + str(msg[0]) + ': ' + msg[1])
        sys.exit() 
    
    return sock


def checksum(msg):  # Following RFC 1071 https://datatracker.ietf.org/doc/html/rfc1071
    s = 0
    for i in range(0, len(msg), 2):
        s = s + ord((chr)(msg[i])) + (ord((chr)(msg[i + 1])) << 8)
    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    s = ~s & 0xffff
    return s


def prepare_ethernet_header(src_mac, dest_mac):
    src_mac = binascii.unhexlify(src_mac.replace(':', ''))
    dest_mac = binascii.unhexlify(dest_mac.replace(':', ''))
    pkt_type = 0x0800
    eth_hdr = dest_mac + src_mac + struct.pack("!H", pkt_type)
    return eth_hdr


def prepare_ipv4_header(src_addr, dst_addr):
    len_and_ver = 0x45
    type_of_service = 0x0
    packet_length = 0x3c
    packet_id = random.randint(0, 0xffff)
    frag_flags_and_offset = 0x4000
    ttl = 64
    protocol = 6
    cksm = 0

    ip_hdr = struct.pack("!BBHHHBBH", len_and_ver, type_of_service, packet_length, packet_id, frag_flags_and_offset, ttl, protocol, cksm) + socket.inet_aton(src_addr) + socket.inet_aton(dst_addr)       
    ip_cksm = hex(checksum(ip_hdr))[2:]
    ip_cksm = int("0x" + ip_cksm[2:] + ip_cksm[0:2], 0)
    ip_hdr = struct.pack("!BBHHHBBH", len_and_ver, type_of_service, packet_length, packet_id, frag_flags_and_offset, ttl, protocol, ip_cksm) + socket.inet_aton(src_addr) + socket.inet_aton(dst_addr)
    return ip_hdr


#TODO: Prepare the header with proper header fields and create and return a packet
def prepare_tcp_packet(src_addr, dst_addr, src_mac, dest_mac):
    eth_hdr = prepare_ethernet_header(src_mac, dest_mac)
    ipv4_hdr = prepare_ipv4_header(src_addr, dst_addr)
        
    src_port = random.randint(0, 65535)
    dst_port = 14742
    seq_num = random.randint(0,0xffffffff)
    ack_num = 0
    data_offset_padding = 0xA0
    flags = 0x002
    rx_window = 64240
    urgent = 0
    tcp_cksm = 0x0
    
    # Adding Option Bytes
    min_seg_size = 2
    seg_size = 4
    mss_val = 1460
    kind = 4 
    sck_len = 2
    time_stamp_opt = 8
    time_stamp_len = 10
    timestamp = random.randint(0,0xffffffff)
    time_stamp_echo_reply = 0
    nop = 1
    win_scale = 3
    win_len = 3
    shift_cnt = 7

    opt_hdr = struct.pack("!BBHBBBBLLBBBB", min_seg_size, seg_size, mss_val, kind, sck_len, time_stamp_opt, time_stamp_len, timestamp, time_stamp_echo_reply,nop, win_scale, win_len, shift_cnt)
    pseudo_hdr = socket.inet_aton(src_addr) + socket.inet_aton(dst_addr) + struct.pack("!BBH", 0x0, 6, 40)    
    tcp_hdr = struct.pack("!HHLLBBHHH", src_port, dst_port, seq_num, ack_num, data_offset_padding, flags, rx_window, 0x0, urgent)
    
    calc_cksm = hex(checksum(pseudo_hdr+tcp_hdr + opt_hdr))[2:]
    calc_cksm = int("0x" + calc_cksm[2:] + calc_cksm[0:2], 0)
    tcp_hdr = struct.pack("!HHLLBBHHH", src_port, dst_port, seq_num, ack_num, data_offset_padding, flags, rx_window, calc_cksm, urgent)

    #print("tcp_cksm ", calc_cksm, hex(calc_cksm))

    pkt = eth_hdr + ipv4_hdr + tcp_hdr  + opt_hdr

    #print(binascii.hexlify(pkt))
    return pkt


def send_packet(sock, pkt):
    sock.send(pkt)

if __name__ == "__main__":

    destination_host_list = [
        ("10.0.1.20", "00:00:00:aa:00:03")
    ]
    
    
    src_addr = "10.0.0.20"
    src_mac  = "00:00:00:aa:00:04"

    sock = setup_connection()
    
    for host in destination_host_list:
        #print(host)
        dst_addr, dest_mac = host     
        pkt = prepare_tcp_packet(src_addr, dst_addr, src_mac, dest_mac)
        
        send_packet(sock, pkt)
    
    sock.close()    

