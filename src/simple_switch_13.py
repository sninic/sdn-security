import eventlet
eventlet.monkey_patch()

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ipv4
import logging

class IPDoSDetectionSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(IPDoSDetectionSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.logger.setLevel(logging.DEBUG)

        # Data structures for detection
        self.datapaths = {}
        self.packet_counts = {}
        self.malicious_ips = set()

        # Threshold for DoS detection
        self.dos_threshold = 100000

        # Start monitoring thread
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Set up default (table-miss) flow entry when the switch connects.
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info("Switch connected: DPID=%s", datapath.id)

        # Table-miss flow sends unknown packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """
        Helper to add flow entries to the switch.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    buffer_id=buffer_id,
                                    priority=priority,
                                    match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    priority=priority,
                                    match=match,
                                    instructions=inst)
        self.logger.debug("Adding flow: DPID=%s priority=%d match=%s actions=%s",
                          datapath.id, priority, match, actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """
        Keep track of datapaths as they connect or disconnect.
        """
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            self.logger.info("Datapath %s connected", datapath.id)
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                self.logger.info("Datapath %s disconnected", datapath.id)

    def _monitor(self):
        """
        Periodically request flow statistics.
        """
        while True:
            for dp in list(self.datapaths.values()):
                self._request_flow_stats(dp)
            # Sleep for 10 seconds between stats requests
            hub.sleep(10)

    def _request_flow_stats(self, datapath):
        """
        Send a FlowStatsRequest to the switch.
        """
        self.logger.debug('Sending stats request to datapath: %016x', datapath.id)
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """
        Handle FlowStatsReply to detect DoS attacks based on IP addresses.
        """
        body = ev.msg.body
        self.logger.debug('FlowStatsReply from DPID=%016x', ev.msg.datapath.id)

        new_counts = {}

        for stat in body:
            self.logger.debug("Flow stat match fields: %s priority=%d packet_count=%d",
                              stat.match, stat.priority, stat.packet_count)
            # Ignore table-miss entries
            if stat.priority == 0:
                continue

            # Extract IPv4 source from match fields (if present)
            src_ip = stat.match.get('ipv4_src')
            if src_ip:
                new_counts[src_ip] = new_counts.get(src_ip, 0) + stat.packet_count

        # Compare with old counts and detect attacks
        for src_ip, new_count in new_counts.items():
            old_count = self.packet_counts.get(src_ip, 0)
            delta = new_count - old_count
            self.packet_counts[src_ip] = new_count

            self.logger.debug("src_ip=%s old_count=%d new_count=%d delta=%d", src_ip, old_count, new_count, delta)

            if delta > self.dos_threshold and src_ip not in self.malicious_ips:
                self.logger.warning("DoS attack detected from %s (packets in last interval: %d)", src_ip, delta)
                self.mitigate_attack(ev.msg.datapath, src_ip)
            elif src_ip in self.malicious_ips:
                self.logger.warning("Drop packets from previously recorded malicious IP: %s (packets in last interval: %d)", src_ip, delta)
            else:
                self.logger.info("Traffic from %s below threshold (delta=%d)", src_ip, delta)

    def mitigate_attack(self, datapath, src_ip):
        """
        Mitigate by installing a drop rule for the malicious source IP.
        This drop rule is implemented at a high priority, so the switch
        drops malicious packets at the data plane without sending them to the controller.
        """
        self.logger.info("Installing drop rule for IP %s", src_ip)
        self.malicious_ips.add(src_ip)

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Match packets from the malicious IP
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        actions = []  # No actions = drop

        # High priority ensures this rule matches before any other rule
        self.add_flow(datapath, priority=100, match=match, actions=actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Handle Packet-In messages for normal learning switch behavior.
        Malicious IP packets are no longer seen by the controller after mitigation,
        because they are dropped at the switch level.
        """
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocols(ethernet.ethernet)[0]

        # Attempt to parse IP layer (not strictly necessary here)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        src_ip = ip_pkt.src if ip_pkt else None
        dst_ip = ip_pkt.dst if ip_pkt else None

        dst = eth_pkt.dst
        src = eth_pkt.src

        self.mac_to_port.setdefault(dpid, {})

        self.logger.debug("Packet in DPID:%s SRC_MAC:%s DST_MAC:%s IN_PORT:%s SRC_IP:%s DST_IP:%s", 
                          dpid, src, dst, in_port, src_ip, dst_ip)

        # Learning switch logic
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            self.logger.debug("Known DST MAC: %s, forwarding to port %s", dst, out_port)
        else:
            out_port = ofproto.OFPP_FLOOD
            self.logger.debug("Unknown DST MAC: %s, flooding", dst)

        actions = [parser.OFPActionOutput(out_port)]

        # If IP present, match flows by IP to gather IP-based stats
        if ip_pkt:
            match = parser.OFPMatch(
                in_port=in_port,
                eth_type=0x0800,
                ipv4_src=ip_pkt.src,
                ipv4_dst=ip_pkt.dst
            )
        else:
            # For non-IP traffic
            match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)

        if out_port != ofproto.OFPP_FLOOD:
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, priority=1, match=match, actions=actions, buffer_id=msg.buffer_id)
                return
            else:
                self.add_flow(datapath, priority=1, match=match, actions=actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out_pkt = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out_pkt)
