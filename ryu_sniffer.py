from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.topology import event

from collections import defaultdict

import random


SNIFFER_SWITCH = int(input("Enter Sniffer Switch : "))
SNIFFER_PORT = int(input("Enter Sniffer Port : "))
print("Entered Sniffer Details:\n","Sniffer connected to switch",SNIFFER_SWITCH,"at port",SNIFFER_PORT)


class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        '''
            Data structures to store network information
        '''
        super(ProjectController, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.datapath_list = {}
        self.arp_table = {}
        self.switches = []
        self.hosts = {}
        self.multi_group_id = {}
        self.group_ids = []
        self.adjacency = defaultdict(dict)

    def bfs_shortest_path(self,start,goal):
        '''
            To find shortest path between 2 switches identified by start and goal
        '''
        explored = []
        queue = [[start]]
        
        if start == goal:
            return [start]
        
        while queue:
            path = queue.pop(0)
            node = path[-1]
            if node not in explored:
                neighbours = self.adjacency[node].keys()
                for neighbour in neighbours:
                    new_path = list(path)
                    new_path.append(neighbour)
                    queue.append(new_path)
                    if neighbour == goal:
                        return new_path
            explored.append(node)
    
    def get_ports(self,path,first_port,last_port):
        '''
            Get input and output port of each switch in path
        '''
        d = {}

        portin = first_port
        for i in range(len(path)-1):
            portout = self.adjacency[path[i]][path[i+1]]
            d[path[i]] = (portin,portout)
            portin = self.adjacency[path[i+1]][path[i]]
        d[path[-1]] = (portin,last_port)

        return d



    def add_ports_to_paths(self, paths, first_port, last_port):
        '''
            Merge the switch list paths and switchwise port information
        '''
        print("paths = ", paths)
        paths_p = []
        paths_p.append(self.get_ports(paths[0],first_port,last_port))
        paths_p.append(self.get_ports(paths[1],first_port,SNIFFER_PORT))
        return paths_p

    def generate_gid(self):
        '''
            Generate new group ID.
        '''
        n = random.randint(0, 2**32)
        while n in self.group_ids:
            n = random.randint(0, 2**32)
        return n

#---------------------------------PATH INSTALLATION------------------------------------------
    def cal_path(self, src, first_port, dst, last_port, ip_src, ip_dst):
        '''
            Generate paths and install flows in each switch
        '''
        paths = []
        paths.append(self.bfs_shortest_path(src, dst))
        paths.append(self.bfs_shortest_path(src,SNIFFER_SWITCH))

        paths_ports = self.add_ports_to_paths(paths, first_port, last_port)
        
        print("switches_with_ports",paths_ports)
        
        flat_paths = [ item for elem in paths for item in elem ]

        '''
        Iterate through all the switches present in the path
        if a switch is present in two paths install 
        a group flow at that switch else insatll a normal path.
        '''

        for node in set(flat_paths):

            dp = self.datapath_list[node]
            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser

            ports = defaultdict(list)
            actions = []

            for path in paths_ports:
                if node not in path:
                    continue
                in_port = path[node][0]
                out_port = path[node][1]
                if out_port in ports[in_port]:
                    continue
                ports[in_port].append(out_port)

            for in_port in ports:

                match_ip = ofp_parser.OFPMatch(
                    eth_type=0x0800, 
                    ipv4_src=ip_src, 
                    ipv4_dst=ip_dst
                )
                
                match_arp = ofp_parser.OFPMatch(
                    eth_type=0x0806, 
                    arp_spa=ip_src, 
                    arp_tpa=ip_dst
                )

                out_ports = ports[in_port]

                if len(out_ports) == 1:
                    actions = [ofp_parser.OFPActionOutput(out_ports[0])]

                    self.add_flow(dp, 32768, match_ip, actions)
                    self.add_flow(dp, 1, match_arp, actions)

                elif len(out_ports) > 1:
                    group_id = None
                    is_group_new = False

                    if (node,(src,first_port),(dst,last_port)) in self.multi_group_id:
                        pass
                    else:
                        is_group_new = True
                        self.multi_group_id[node,(src,first_port),(dst,last_port)] = self.generate_gid()
                    
                    group_id = self.multi_group_id[node,(src,first_port),(dst,last_port)]

                    buckets = []
                    # print "node at ",node," out ports : ",out_ports
                    for port in out_ports:
                        bucket_action = [ofp_parser.OFPActionOutput(port)]
                        buckets.append(
                            ofp_parser.OFPBucket(
                                actions=bucket_action
                            )
                        )

                    if is_group_new:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id,
                            buckets)
                        dp.send_msg(req)
                    else:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_MODIFY, ofp.OFPGT_ALL,
                            group_id, buckets)
                        dp.send_msg(req)

                    actions = [ofp_parser.OFPActionGroup(group_id)]

                    self.add_flow(dp, 32768, match_ip, actions)
                    self.add_flow(dp, 1, match_arp, actions)
        
        return paths_ports[0][src][1]


#--------------------------------Add Flow Method----------------------------------
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        '''
            Method to add flow to switch
        '''
        # print "Adding flow ", match, actions
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

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        # print("switch_features_handler is called")
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        '''
            Main Handler
        
        '''
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)

        if eth.ethertype == 35020:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        if src not in self.hosts:
            self.hosts[src] = (dpid, in_port)

        out_port = ofproto.OFPP_FLOOD

        if arp_pkt:
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            if arp_pkt.opcode == arp.ARP_REPLY:
                self.arp_table[src_ip] = src
                h1 = self.hosts[src]
                h2 = self.hosts[dst]
                out_port = self.cal_path(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
                self.cal_path(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip) # reverse
            elif arp_pkt.opcode == arp.ARP_REQUEST:
                if dst_ip in self.arp_table:
                    self.arp_table[src_ip] = src
                    dst_mac = self.arp_table[dst_ip]
                    h1 = self.hosts[src]
                    h2 = self.hosts[dst_mac]
                    out_port = self.cal_path(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
                    self.cal_path(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip) # reverse

        # print(pkt)

        actions = [parser.OFPActionOutput(out_port)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

#-----------------------TOPOLOGY UPDATE METHODS--------------------
    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, event):
        switch = event.switch.dp
        ofp_parser = switch.ofproto_parser
        print(switch)

        if switch.id not in self.switches:
            self.switches.append(switch.id)
            self.datapath_list[switch.id] = switch #getting switch object for calculating paths


    @set_ev_cls(event.EventSwitchLeave)
    def switch_leave_handler(self, event):
        # print(event)
        switch = event.switch.dp.id
        if switch in self.switches:
            del self.switches[switch]
            del self.datapath_list[switch]
            del self.adjacency[switch]

    @set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, event):
        print(event)
        s1 = event.link.src
        s2 = event.link.dst
        self.adjacency[s1.dpid][s2.dpid] = s1.port_no
        self.adjacency[s2.dpid][s1.dpid] = s2.port_no

    @set_ev_cls(event.EventLinkDelete)
    def link_delete_handler(self, event):
        s1 = event.link.src
        s2 = event.link.dst
        del self.adjacency[s1.dpid][s2.dpid]
        del self.adjacency[s2.dpid][s1.dpid]