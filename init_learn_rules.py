from re import sub, subn
from struct import *
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4, icmp, tcp
from datetime import datetime
from os.path import exists
import os, sys

log_file_path = "/home/ini742/Desktop/NetSec/14742-lab3-part2-RaviNayyar/cntrl_log_file.csv"


connection_list = {}

controller_statistics = {}


def init_stats_structure(host):    
    if host in controller_statistics.keys():
        return

    controller_statistics[host] = {
        "icmp" : [None,  # Time of first recorded ICMP request packet in this interval
                  None,  # Number of ICMP request packets in this interval
                  None,  # Time since rate limiting started for ICMP request packets for this connection
                  False, # Boolean flag for if rate limiting has been started for this connection

                  None,  # Time of first recorded ICMP reply packet in this interval
                  None,  # Number of ICMP reply packets in this interval
                  None,  # Time since rate limitign started for ICMP reply packets for this connection
                  False],# Boolean flag for if rate limiting has been started for this connection  

        "tcp"  : [None,  # Time of first recorded TCP packet in this interval
                  None,  # Number of TCP packets in this interval
                  None,  # Time since rate limiting started for ICMP request packets for this connection
                  False, # Boolean flag for if rate limiting has been started for this connection
                  ]
    }


def get_time_difference(time1, time2):
    pass

def update_stats(pkt_type, ip_src):
    controller_statistics
    pass


class InitLearnRules(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(InitLearnRules, self).__init__(*args, **kwargs)
        self.port_addrs ={ 
        11141120: {1: {'eth': ["00:00:00:aa:00:0d"], 'ip' : ['10.0.4.2']}, 
                   2: {'eth': ["00:00:00:aa:00:11"], "ip" : ["10.0.6.2"]},
                   3: {'eth': ["00:00:00:aa:00:11"], "ip" : ["10.0.6.2"]}
                },
        11141121: {1: {'eth': ['00:00:00:aa:00:0c'], 'ip' : ["10.0.4.1"]}, 
                   2: {'eth': ["00:00:00:aa:00:13"], "ip" : ["10.0.7.2"]},
                   3: {'eth': ["00:00:00:aa:00:13"], "ip" : ["10.0.7.2"]}
                },        
        11141122: {1: {'eth': ['00:00:00:aa:00:10'], 'ip' : ["10.0.6.1"]}, 
                   2: {'eth': ["00:00:00:aa:00:0f"], "ip" : ["10.0.5.2"]},
                   3: {'eth': ["00:00:00:aa:00:0f"], "ip" : ["10.0.5.2"]}
                },  
        11141123: {1: {'eth': ['00:00:00:aa:00:0e'], 'ip' : ['10.0.5.1']}, 
                   2: {'eth': ["00:00:00:aa:00:12"], "ip" : ["10.0.7.1"]},
                   3: {'eth': ["00:00:00:aa:00:12"], "ip" : ["10.0.7.1"]}
                },  
        }
                
        self.sw_addrs = {11141120: {1: {'eth': '00:00:00:aa:00:00', 'ip': '10.0.0.1'}, 2: {'eth': '00:00:00:aa:00:0c', 'ip': '10.0.4.1'}, 3:  {'eth': '00:00:00:aa:00:10', 'ip': '10.0.6.1'}},
                         11141121: {1: {'eth': '00:00:00:aa:00:01', 'ip': '10.0.1.1'}, 2: {'eth': '00:00:00:aa:00:0d', 'ip': '10.0.4.2'}, 3:  {'eth': '00:00:00:aa:00:12', 'ip': '10.0.7.1'}},       
                         11141122: {1: {'eth': '00:00:00:aa:00:02', 'ip': '10.0.2.1'}, 2: {'eth': '00:00:00:aa:00:0e', 'ip': '10.0.5.1'}, 3: {'eth': '00:00:00:aa:00:11', 'ip' : '10.0.6.2'}},
                         11141123: {1: {'eth': '00:00:00:aa:00:03', 'ip': '10.0.3.1'}, 2: {'eth': '00:00:00:aa:00:0f', 'ip': '10.0.5.2'}, 3: {'eth': '00:00:00:aa:00:13', 'ip' : '10.0.7.2'}}}
        
        self.whitelist = ["10.0.0.0", "10.0.3.0"]
        
        self.pkt_time_interval = 2
        self.pkt_threshold = self.pkt_time_interval * 5
        
        self.syn_flood  = False
        self.icmp_flood = False


    def attack_detected(self, msg):
        print("ATTACK DETECTED: " + msg+"\n")
        return


    def write_to_logfile(self, packet_type="", dpid="", src_mac="", src_ip="", dst_mac="", dst_ip="", comment="", attack="", p2c=False):
        if not exists(log_file_path):
            csv_header = "date_time, packet_type, dpid, src_mac, src_ip, dst_mac, dst_ip, comment\n"
            f = open(log_file_path, "w")
            f.write(csv_header)
            f.close()
            return
        
        message = "{}, {}, {}, {}, {}, {}, {}, {}\n".format(datetime.now(), packet_type, dpid, src_mac, src_ip, dst_mac, dst_ip, comment)
        if p2c:
            print(message)
        
        if attack != "":
            f = open(log_file_path, "a")
            attk = "ATTACK DETECTED: " + attack + "\n" + "Starting rate limiting\n"
            f.write("="*50 + "\n")
            f.write(attk)
            f.write(message)
            f.write("="*50 + "\n")
            f.close()      
            return

        f = open(log_file_path, "a")
        
        

        f.write(message)
        f.close()


    def convert_ip_to_subnet(self, curr_ip):
        curr_ip = curr_ip.split('.')
        curr_ip[-1] = '0'
        ip_subnet = '.'.join(curr_ip)
        return ip_subnet


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        par = dp.ofproto_parser
        act = [par.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [par.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, act)]
        dp.send_msg(par.OFPFlowMod(datapath=dp, priority=0, match=par.OFPMatch(), instructions=inst))
#        self.logger.info("switch set up with datapath %s", dp.id)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _pkt_in(self, ev):
        
        msg = ev.msg
        dp = msg.datapath
        inp = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        
        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        if not pkt_eth:
            return

        if dp.id not in self.port_addrs:
            self.port_addrs[dp.id] = {}        

        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            self._arp_in(dp, inp, pkt_eth, pkt_arp)
            return

        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)

        pkt_icmp = pkt.get_protocol(icmp.icmp)
        
        try:
            if [dp.id, pkt_ipv4.src, pkt_ipv4.dst] not in connection_list.values():
                connection_list[len(connection_list)] = [dp.id, pkt_ipv4.src, pkt_ipv4.dst]
            init_stats_structure(len(connection_list)-1)
        except Exception as e:
            pass

        if pkt_icmp:
            self._icmp_in(dp, inp, pkt_eth, pkt_ipv4, pkt_icmp)
            return
        
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        if pkt_tcp:
            self._tcp_in(pkt, dp, inp, pkt_eth, pkt_ipv4, pkt_tcp)
            return

    
    def _arp_in(self, dp, inp, pkt_eth, pkt_arp):        

        par = dp.ofproto_parser
        ofp = dp.ofproto
        match = par.OFPMatch(in_port=inp, 
                             eth_type=0x0806, 
                             arp_op=arp.ARP_REQUEST,
                             eth_src=pkt_eth.src,
                             arp_tpa=self.sw_addrs[dp.id][inp]['ip'])
        act = [par.OFPActionSetField(eth_dst=pkt_eth.src),
               par.OFPActionSetField(eth_src=self.sw_addrs[dp.id][inp]['eth']), 
               par.OFPActionSetField(arp_op=arp.ARP_REPLY), 
               par.OFPActionSetField(arp_tha=pkt_eth.src),
               par.OFPActionSetField(arp_sha=self.sw_addrs[dp.id][inp]['eth']), 
               par.OFPActionSetField(arp_tpa=pkt_arp.src_ip), 
               par.OFPActionSetField(arp_spa=self.sw_addrs[dp.id][inp]['ip']),
               par.OFPActionOutput(ofp.OFPP_IN_PORT)]
        inst = [par.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, act)]
                  
        dp.send_msg(par.OFPFlowMod(datapath=dp, priority=1, match=match, instructions=inst))


    def _icmp_in(self, dp, inp, pkt_eth, pkt_ipv4, pkt_icmp):
        comment = ""
        if pkt_icmp.type != icmp.ICMP_ECHO_REQUEST and pkt_icmp.type != icmp.ICMP_ECHO_REPLY:
            return

        # self.logger.info("icmp ping msg from %s",pkt_ipv4.src) 
        # keep track of mac/ip pair
        dpid = dp.id
        if inp not in self.port_addrs[dpid]:
            self.port_addrs[dpid][inp] = {}
            self.port_addrs[dpid][inp]['eth'] = [pkt_eth.src]
            self.port_addrs[dpid][inp]['ip'] = [pkt_ipv4.src]
        elif pkt_ipv4.src not in self.port_addrs[dpid][inp]['ip']:
            self.port_addrs[dpid][inp]['eth'].append(pkt_eth.src)
            self.port_addrs[dpid][inp]['ip'].append(pkt_ipv4.src)
        
        # pinging the switch itself
        first_key = list(self.sw_addrs[dpid].keys())[0]
        self_dict = self.sw_addrs[dpid][first_key]

        if pkt_icmp.type == icmp.ICMP_ECHO_REQUEST and pkt_ipv4.dst == self_dict['ip']:
            pkt_icmp_reply = packet.Packet()
            pkt_icmp_reply.add_protocol(ethernet.ethernet(ethertype=pkt_eth.ethertype,
                                                          dst=pkt_eth.src,
                                                          src=self_dict['eth']))
            pkt_icmp_reply.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,
                                                  src=self_dict['ip'],
                                                  proto=pkt_ipv4.proto))
            pkt_icmp_reply.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,
                                                  code=icmp.ICMP_ECHO_REPLY_CODE,
                                                  csum=0,
                                                  data=pkt_icmp.data))
            
            self.write_to_logfile("ICMP", dpid, pkt_eth.dst, pkt_ipv4.src, pkt_eth.src, pkt_ipv4.dst, comment="Switch is pinging itself") 

            self._pkt_out(dp, inp, pkt_icmp_reply)

            return

        # ping request to or reply from a node in a different subnet
        dpid_dict = self.sw_addrs[dpid]
        icmp_subnet = self.convert_ip_to_subnet(pkt_ipv4.dst)
        sw_subnet = self.convert_ip_to_subnet(dpid_dict[inp]['ip'])

        if icmp_subnet != sw_subnet:
            outp = 0
            
            routes = []
            for curr_dpid in self.sw_addrs:
                if curr_dpid == dpid: continue
                if self.convert_ip_to_subnet(self.sw_addrs[curr_dpid][1]["ip"]) == icmp_subnet:
                    routes = [self.convert_ip_to_subnet(self.sw_addrs[curr_dpid][2]["ip"]), self.convert_ip_to_subnet(self.sw_addrs[curr_dpid][3]["ip"])]
                    break 
            for port in dpid_dict:
                port_subnet = self.convert_ip_to_subnet(dpid_dict[port]['ip'])
                if port_subnet in routes:
                    outp = port  
                if port_subnet == icmp_subnet:
                    outp = port
                    comment = "Packet has reached its destination"
                    break
                       
            if outp == 0:
                outp = 3
            
            dpid = dp.id
            pkt_icmp_fwd = packet.Packet()
            dmac = 'ff:ff:ff:ff:ff:ff'
            if outp in self.port_addrs[dpid] and pkt_ipv4.dst in self.port_addrs[dpid][outp]['ip']:
                idx = self.port_addrs[dpid][outp]['ip'].index(pkt_ipv4.dst)
                dmac = self.port_addrs[dpid][outp]['eth'][idx]
                
            pkt_icmp_fwd.add_protocol(ethernet.ethernet(ethertype=pkt_eth.ethertype,
                                                        dst=dmac,
                                                        src=dpid_dict[outp]['eth']))

            pkt_icmp_fwd.add_protocol(ipv4.ipv4(dst=pkt_ipv4.dst,
                                                src=pkt_ipv4.src,
                                                proto=pkt_ipv4.proto))

            pkt_icmp_fwd.add_protocol(icmp.icmp(type_=pkt_icmp.type,
                                                code=pkt_icmp.code,
                                                csum=0,
                                                data=pkt_icmp.data))
            
            pkt_type = ""
            adj = 0 # adjusts which feilds in the controller stats gets adjusted
            if pkt_icmp.type == icmp.ICMP_ECHO_REQUEST:
                pkt_type = "ICMP ECHO REQUEST"   
            elif pkt_icmp.type == icmp.ICMP_ECHO_REPLY:
                pkt_type = "ICMP ECHO REPLY  "
                adj = 4
            
            # Adding statistics to the controller data structrue
            idx = list(connection_list.values()).index([dpid, pkt_ipv4.src, pkt_ipv4.dst])
            icmp_data = controller_statistics[idx]["icmp"]
            if icmp_data[0+adj] != None:
                # Checking to see if the interval has elapsed
                if ((datetime.now()-icmp_data[0+adj]).seconds > self.pkt_time_interval):                        
                    # Check if the ICMP pkt threshold has been breached
                    if icmp_data[1+adj] > self.pkt_threshold:
                        if not self.icmp_flood:
                            self.attack_detected("ICMP FLood Attack Detected")
                            self.write_to_logfile(pkt_type, dpid, pkt_eth.dst, pkt_ipv4.src, pkt_eth.src, pkt_ipv4.dst, comment, attack="ICMP FLood Attack Detected", p2c=True) 
                            self.icmp_flood = True
                        # Setting rate limiting to `True 
                        icmp_data[2+adj] = datetime.now() 
                        icmp_data[3+adj] = True 

                    # Resetting values for a new interval
                    icmp_data[0+adj] = datetime.now()
                    icmp_data[1+adj] = 1
                
                else:
                    # Interval has not yet elapsed 
                    icmp_data[1+adj] += 1
            
            else:
                # Initialize None type fields
                icmp_data[0+adj] = datetime.now()
                icmp_data[1+adj] = 1
            

            # If rate limiting is enabled and the two second limiting period has not yet elapsed
            if icmp_data[3+adj] ==  True: 
                if ((datetime.now() - icmp_data[2+adj]).seconds <= 2):
                    if icmp_data[1+adj] > 2:
                        self.write_to_logfile(pkt_type, dpid, pkt_eth.dst, pkt_ipv4.src, pkt_eth.src, pkt_ipv4.dst, comment= "Dropped During Rate Limiting") 
                        return

                    self.write_to_logfile(pkt_type, dpid, pkt_eth.dst, pkt_ipv4.src, pkt_eth.src, pkt_ipv4.dst, comment= "Sent During Rate Limiting") 
                    self._pkt_out(dp, outp, pkt_icmp_fwd)

                    return
                else:
                    # Resetting rate limiting feilds
                    icmp_data[2+adj] = None
                    icmp_data[3+adj] = None
            
            self.write_to_logfile(pkt_type, dpid, pkt_eth.dst, pkt_ipv4.src, pkt_eth.src, pkt_ipv4.dst, comment) 
            self._pkt_out(dp, outp, pkt_icmp_fwd)
            self.icmp_flood = False
            return
    
    '''Citations
    https://ryu.readthedocs.io/en/latest/library_packet_ref/packet_tcp.html
    
    '''
    def _tcp_in(self, pkt, dp, inp, pkt_eth, pkt_ipv4, pkt_tcp):
        comment = ""
        # keep track of mac/ip pair
        dpid = dp.id
        if inp not in self.port_addrs[dpid]:
            self.port_addrs[dpid][inp] = {}
            self.port_addrs[dpid][inp]['eth'] = [pkt_eth.src]
            self.port_addrs[dpid][inp]['ip'] = [pkt_ipv4.src]
        elif pkt_ipv4.src not in self.port_addrs[dpid][inp]['ip']:
            self.port_addrs[dpid][inp]['eth'].append(pkt_eth.src)
            self.port_addrs[dpid][inp]['ip'].append(pkt_ipv4.src)

        # ping request to or reply from a node in a different subnet
        dpid_dict = self.sw_addrs[dpid]
        tcp_subnet = self.convert_ip_to_subnet(pkt_ipv4.dst)
        sw_subnet = self.convert_ip_to_subnet(dpid_dict[inp]['ip'])
        
        if self.convert_ip_to_subnet(pkt_ipv4.src) not in self.whitelist:
            return

        if tcp_subnet != sw_subnet:
            outp = 0
            
            routes = []
            for curr_dpid in self.sw_addrs:
                if curr_dpid == dpid: continue
                if self.convert_ip_to_subnet(self.sw_addrs[curr_dpid][1]["ip"]) == tcp_subnet:
                    routes = [self.convert_ip_to_subnet(self.sw_addrs[curr_dpid][2]["ip"]), self.convert_ip_to_subnet(self.sw_addrs[curr_dpid][3]["ip"])]
                    break 
            for port in dpid_dict:
                port_subnet = self.convert_ip_to_subnet(dpid_dict[port]['ip'])
                if port_subnet in routes:
                    outp = port  
                if port_subnet == tcp_subnet:
                    comment = "Packet has reached its destination"
                    outp = port
                    break
                        
            if outp == 0:
                outp = 3
            

            dpid = dp.id
            pkt_tcp_fwd = packet.Packet()
            dmac = 'ff:ff:ff:ff:ff:ff'
            if outp in self.port_addrs[dpid] and pkt_ipv4.dst in self.port_addrs[dpid][outp]['ip']:
                idx = self.port_addrs[dpid][outp]['ip'].index(pkt_ipv4.dst)
                dmac = self.port_addrs[dpid][outp]['eth'][idx]

            pkt_tcp_fwd.add_protocol(ethernet.ethernet(ethertype=pkt_eth.ethertype, dst=dmac, src=dpid_dict[outp]['eth']))
            pkt_tcp_fwd.add_protocol(ipv4.ipv4(version=pkt_ipv4.version, header_length=pkt_ipv4.header_length,tos=pkt_ipv4.tos, total_length=pkt_ipv4.total_length, 
                                                identification=pkt_ipv4.identification, flags=pkt_ipv4.flags, offset=pkt_ipv4.offset, ttl=pkt_ipv4.ttl, proto=pkt_ipv4.proto, csum=pkt_ipv4.csum, 
                                                    src=pkt_ipv4.src, dst=pkt_ipv4.dst, option=pkt_ipv4.option))
            pkt_tcp_fwd.add_protocol(tcp.tcp(ack=pkt_tcp.ack, bits=pkt_tcp.bits, csum=pkt_tcp.csum, dst_port=pkt_tcp.dst_port, option=pkt_tcp.option, seq=pkt_tcp.seq,
                                                src_port=pkt_tcp.src_port, urgent=pkt_tcp.urgent, window_size=pkt_tcp.window_size))
            

            # Citation: https://piazza.com/class/kxzd1kggr9w3m?cid=139
            if type(pkt.protocols[-1]) is bytes:
                payload = pkt.protocols[-1]
                if payload is not None:
                    pkt_tcp_fwd.add_protocol(payload)


            # Adding statistics to the controller data structrue
            idx = list(connection_list.values()).index([dpid, pkt_ipv4.src, pkt_ipv4.dst])
            tcp_data = controller_statistics[idx]["tcp"]
            if tcp_data[0] != None:
                # Checking to see if the interval has elapsed
                if ((datetime.now()-tcp_data[0]).seconds > self.pkt_time_interval):
                    # Check if the ICMP pkt threshold has been breached
                    if tcp_data[1] > self.pkt_threshold:
                        if not self.syn_flood:
                            self.attack_detected("TCP SYN Flood Detected")
                            self.write_to_logfile("TCP Packet", dpid, pkt_eth.dst, pkt_ipv4.src, pkt_eth.src, pkt_ipv4.dst, comment, attack="TCP SYN Flood Detected", p2c=True) 
                            self.syn_flood = True
                        # Setting rate limiting to `True 
                        tcp_data[2] = datetime.now() 
                        tcp_data[3] = True 

                    # Resetting values for a new interval
                    tcp_data[0] = datetime.now()
                    tcp_data[1] = 1
                
                else:
                    # Interval has not yet elapsed 
                    tcp_data[1] += 1
            
            else:
                # Initialize None type fields
                tcp_data[0] = datetime.now()
                tcp_data[1] = 1


            # If rate limiting is enabled and the two second limiting period has not yet elapsed
            if tcp_data[3] ==  True: 
                if ((datetime.now() - tcp_data[2]).seconds <= 2):
                    if tcp_data[1] > 2:
                        self.write_to_logfile("TCP Packet", dpid, pkt_eth.dst, pkt_ipv4.src, pkt_eth.src, pkt_ipv4.dst, comment= "Dropped During Rate Limiting") 
                        return
                        
                    self.write_to_logfile("TCP Packet", dpid, pkt_eth.dst, pkt_ipv4.src, pkt_eth.src, pkt_ipv4.dst, comment = "Sent During Rate Limiting") 
                    self._pkt_out(dp, outp, pkt_tcp_fwd)

                    return
                else:
                    # Resetting rate limiting feilds
                    tcp_data[2] = None
                    tcp_data[3] = None
            
            self.write_to_logfile("TCP Packet", dpid, pkt_eth.dst, pkt_ipv4.src, pkt_eth.src, pkt_ipv4.dst, comment) 
            self._pkt_out(dp, outp, pkt_tcp_fwd)
            self.syn_flood = False
            comment = ""
            return



    def _pkt_out(self, dp, prt, pkt):
        ofp = dp.ofproto
        par = dp.ofproto_parser        
        pkt.serialize()
#        self.logger.info("packet-out %s", pkt)
        dp.send_msg(par.OFPPacketOut(datapath=dp, 
                                     buffer_id=ofp.OFP_NO_BUFFER,
                                     in_port=ofp.OFPP_CONTROLLER,
                                     actions=[par.OFPActionOutput(port=prt)],
                                     data=pkt.data))