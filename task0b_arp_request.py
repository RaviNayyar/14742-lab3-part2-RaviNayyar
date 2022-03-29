#!/usr/bin/env python3
'''
Citations

https://docs.python.org/3/library/binascii.html
'''


import socket, sys, time, struct
import binascii


def setup_connection():
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.bind(("eth0",0))
    except socket.error as msg:
        print('error ' + str(msg[0]) + ': ' + msg[1])
        sys.exit() 
    return sock


#TODO: Prepare the header with proper header fields and create and return a packet
def prepare_arp_packet(src_IP, dest_IP):
    src_mac  = "00:00:00:aa:00:00"
    dest_mac = "ff:ff:ff:ff:ff:ff"
    src_mac = binascii.unhexlify(src_mac.replace(':', ''))
    dest_mac = binascii.unhexlify(dest_mac.replace(':', ''))
    pkt_type = 0x0806
    eth_hdr = dest_mac + src_mac + struct.pack("!H", pkt_type)
    
    hw_type = 0x01
    proto_type = 0x0800
    hw_size = 0x6
    proto_size = 0x4
    opcode = 0x1
    trgt_mac = "00:00:00:00:00:00" 
    trgt_mac = binascii.unhexlify(trgt_mac.replace(':', ''))        
    arp_hdr = struct.pack("!HHBBH", hw_type, proto_type, hw_size, proto_size, opcode) + src_mac + socket.inet_aton(src_IP) + trgt_mac + socket.inet_aton(dest_IP)
    pkt = eth_hdr + arp_hdr
    return pkt


def send_arp_packet(sock, pkt, target_ip):
    sock.send(pkt)


if __name__ == "__main__":
    source_ip = sys.argv[1] #"10.0.0.20"
    target_ip = sys.argv[2] #"10.0.0.21"
    
    sock = setup_connection()
    pkt = prepare_arp_packet(source_ip, target_ip)
    send_arp_packet(sock, pkt, target_ip)
    sock.close()

