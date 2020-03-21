from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


class LoadBalancingSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    # Server IPs and MACs
    h5_mac = "00:00:00:00:00:05"
    h5_ip = "10.0.0.5"
    h6_mac = "00:00:00:00:00:06"
    h6_ip = "10.0.0.6"
    virtual_ip = "10.0.0.10"
    # IPs that correspond to the current and previous servers
    next_ip = ""
    current_ip = ""
    ip_to_mac = {"10.0.0.1": "00:00:00:00:00:01",
                 "10.0.0.2": "00:00:00:00:00:02",
                 "10.0.0.3": "00:00:00:00:00:03",
                 "10.0.0.4": "00:00:00:00:00:04"}
    ip_to_port = {h5_ip: 5, h6_ip: 6}

    def __init__(self, *args, **kwargs):
        """
        Initialize class variables including the current and next server IPs
        :param args:
        :param kwargs:
        """
        super(LoadBalancingSwitch, self).__init__(*args, **kwargs)
        self.next_ip = self.h5_ip
        self.current_ip = self.h5_ip

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Handles incoming packets by setting up appropriate flows and arp responses
        :param ev: incoming event that contains the message
        :return:
        """
        msg = ev.msg
        in_port = msg.match['in_port']
        datapath = msg.datapath
        ofp_parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        pkt = packet.Packet(msg.data)
        ethernet_frame = pkt.get_protocol(ethernet.ethernet)

        # Packet contains ARP request. Add the flow to the table and send response
        if ethernet_frame.ethertype == ether_types.ETH_TYPE_ARP:
            # Flows in both directions are setup only when ARP request is received from client
            # Ignore ARP requests from servers
            source_ip = pkt.get_protocol(arp.arp).src_ip
            if source_ip != self.h5_ip and source_ip != self.h6_ip:
                self.add_client_server_flow(datapath, ofp_parser, ofp, in_port, source_ip)
            self.send_response(datapath, pkt, ethernet_frame, ofp_parser, ofp, in_port, source_ip)
            self.current_ip = self.next_ip
            return
        # Ignore other packets
        else:
            return

    def add_client_server_flow(self, datapath, ofp_parser, ofproto, in_port, source_ip):
        """
        Sets up the flow entry for client to server such that the switch properly maps IP addresses to source and destination IPs/MACs
        :param datapath:
        :param packet:
        :param ofp_parser:
        :param ofproto:
        :param in_port:
        :param source_ip:
        """
        # Create flow entry from host to server
        out_port = self.ip_to_port[self.current_ip]
        match = ofp_parser.OFPMatch(in_port=in_port,
                                    ipv4_dst=self.virtual_ip,
                                    eth_type=0x0800)
        actions = [ofp_parser.OFPActionSetField(ipv4_dst=self.current_ip),
                   ofp_parser.OFPActionOutput(out_port)]
        inst = [ofp_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        # construct flow_mod and send it along datapath
        mod = ofp_parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            buffer_id=ofproto.OFP_NO_BUFFER,
            match=match,
            instructions=inst)

        datapath.send_msg(mod)
        # Add flow in opposite direction
        self.add_server_client_flow(datapath, ofp_parser, ofproto, in_port, source_ip)

    def add_server_client_flow(self, datapath, ofp_parser, ofproto, in_port, source_ip):
        """
        Sets up the flow table for server to client such that the switch properly maps IP addresses to source and destination IPs/MACs
        :param datapath:
        :param packet:
        :param ofp_parser:
        :param ofproto:
        :param in_port:
        :param source_ip:
        """
        # Create flow entry from server to host
        match = ofp_parser.OFPMatch(in_port=self.ip_to_port[self.current_ip],
                                    ipv4_src=self.current_ip,
                                    ipv4_dst=source_ip,
                                    eth_type=0x0800)
        actions = [ofp_parser.OFPActionSetField(ipv4_src=self.virtual_ip),
                   ofp_parser.OFPActionOutput(in_port)]
        inst = [ofp_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = ofp_parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            buffer_id=ofproto.OFP_NO_BUFFER,
            match=match,
            instructions=inst)

        datapath.send_msg(mod)

    def send_response(self, datapath, packet, ethernet_frame, ofp_parser, ofp, in_port, source_ip):
        """
        Sends out an ARP response along the datapath such that hosts map the virtual IP address to the real
        MAC address of a server
        :param datapath:
        :param packet:
        :param ethernet_frame:
        :param ofp_parser:
        :param ofp:
        :param in_port:
        :param source_ip:
        """
        # reverse source and destination IPs/MACs
        arp_packet = packet.get_protocol(arp.arp)
        destination_ip = source_ip
        source_ip = arp_packet.dst_ip
        destination_mac = ethernet_frame.src

        # Update source mac and next IP to alternate with each new host
        if destination_ip != self.h5_ip and destination_ip != self.h6_ip:
            if self.next_ip == self.h5_ip:
                source_mac = self.h5_mac
                self.next_ip = self.h6_ip
            else:
                source_mac = self.h6_mac
                self.next_ip = self.h5_ip
        else:
            source_mac = self.ip_to_mac[source_ip]
        # Construct packet and send response
        e = ethernet.ethernet(destination_mac, source_mac, ether_types.ETH_TYPE_ARP)
        a = arp.arp(1, 0x0800, 6, 4, 2, source_mac, source_ip, destination_mac, destination_ip)
        p = Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_IN_PORT)]
        out = ofp_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=p.data
        )
        datapath.send_msg(out)
