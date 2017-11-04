# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import arp



class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        
        #Creating class variables for storing various attributes
        
        #for storing our three servers' data.This will be 
        #a list of dictionaries, where each dict will have ip, mac and
        #switch's port number to which it is connected.  
        self.list_of_servers = []
        self.list_of_servers.append({'ip':"10.0.0.1", 'mac':"00:00:00:00:00:01", 'switch_port':"1" })
        self.list_of_servers.append({'ip':"10.0.0.2", 'mac':"00:00:00:00:00:02", 'switch_port':"2" })
        self.list_of_servers.append({'ip':"10.0.0.3", 'mac':"00:00:00:00:00:03", 'switch_port':"3" })
        
        #a counter which will keep on increasing as per each
        #packet_in event triggered. It will be used in 
        #round_robin functionality
        self.counter = 0
        
        #variables for load balancer IP and mac i.e. service IP and mac
        self.service_ip = "10.0.0.100"
        self.service_mac ="10:10:10:10:10:10" 
        
    def create_arp_reply(self, source_mac, source_ip):
        
        #print("Data Received: ", source_mac, source_ip)
        src_mac = self.service_mac
        src_ip = self.service_ip
        dst_mac = source_mac    #source(requester) becomes destination
        dst_ip = source_ip
        
        arp_opcode = 2  #opcode for Reply
        
        ethertype = 2054    
        hwtype = 1
        proto = 2048
        hlen = 6
        plen = 4

        pkt = packet.Packet()
        e = ethernet.ethernet(dst_mac, src_mac, ethertype)
        a = arp.arp(hwtype, proto, hlen, plen, arp_opcode,
                    src_mac, src_ip, dst_mac, dst_ip)
        pkt.add_protocol(e)
        pkt.add_protocol(a)
        pkt.serialize()

        return pkt
     

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        self.logger.info("InsidePacketINEvent")
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        #print("Static Data: ", self.service_ip, self.service_mac)
        #print(eth)
        
        #check if the packet_in is an ARP request for service_ip.
        if eth.ethertype == 2054:
            arp_data = pkt.get_protocols(arp.arp)[0]
            #print(arp_data)
            #print(arp_data.dst_ip, arp_data.opcode)
            if (arp_data.dst_ip == self.service_ip and arp_data.opcode == 1):
                print("ARP Request for service_ip received")
                
                #create ARP reply 
                arp_reply = self.create_arp_reply(arp_data.src_mac, arp_data.src_ip)
                #print(arp_reply) 
                
                #to forward the ARP reply on the port on which request was received. 
                actions = [parser.OFPActionOutput(in_port)]
                
                #create packet_out
                out = parser.OFPPacketOut(datapath=datapath, in_port = ofproto.OFPP_ANY, data=arp_reply.data, actions=actions, buffer_id = 0xffffffff)
                
                
                #sending packet out message to forward the packet
                datapath.send_msg(out)
            
            return
              

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
