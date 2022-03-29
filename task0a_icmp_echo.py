#!/usr/bin/env python3

import socket, sys, struct, sys, random

def setup_connection():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except socket.error as msg:
        print('error ' + str(msg[0]) + ': ' + msg[1])
        sys.exit() 
    
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    return sock


def checksum(msg):  # Following RFC 1071 https://datatracker.ietf.org/doc/html/rfc1071
    s = 0
    for i in range(0, len(msg), 2):
        s = s + ord((chr)(msg[i])) + (ord((chr)(msg[i + 1])) << 8)
    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    s = ~s & 0xffff
    return s


def get_ipv4_header(src_addr, dst_addr):
    len_and_ver = int(0x45)
    type_of_service = int(0x0)
    packet_length = int(0x54)
    frag_flags_and_offset = int(0x4000)
    packet_id = random.randint(0, 65535)
    ttl = int(0x40)
    proto_id = int(0x1)

    pre_chksm = struct.pack("!BBHHHBB", len_and_ver, type_of_service, packet_length, packet_id, frag_flags_and_offset, ttl, proto_id)
    ip_checksum = checksum(pre_chksm)
    ipv4_header = struct.pack("!BBHHHBBH", len_and_ver, type_of_service, packet_length, packet_id, frag_flags_and_offset, ttl, proto_id, ip_checksum) + socket.inet_aton(src_addr) + socket.inet_aton(dst_addr)
    return ipv4_header


def prepare_icmp_packet(source_ip, target_ip):
    ipv4_pkt = get_ipv4_header(source_ip, target_ip) 

    icmp_type = 8
    icmp_code = 0
    icmp_cksm = 0
    icmp_id   = 0
    icmp_seq_num  = 1
 
    icmp_hdr = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_cksm, icmp_id, icmp_seq_num)
    calc_cksm = hex(checksum(icmp_hdr))[2:]
    calc_cksm = int("0x" + calc_cksm[2:] + calc_cksm[0:2], 0)
    icmp_pkt = struct.pack("!BBHHH", icmp_type, icmp_code, calc_cksm, icmp_id, icmp_seq_num)

    return ipv4_pkt + icmp_pkt


def send_icmp_packet(sock, pkt, target_ip):
    sock.sendto(pkt, (target_ip, 0))


if __name__ == "__main__":

    source_ip = sys.argv[1] #"10.0.0.20"
    target_ip = sys.argv[2] #"10.0.0.21"

    sock = setup_connection()
    pkt = prepare_icmp_packet(source_ip, target_ip)
    
    send_icmp_packet(sock, pkt, target_ip)
    sock.close()