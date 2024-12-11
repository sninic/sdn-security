import eventlet
eventlet.monkey_patch()

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
from ryu.lib import hub
from ryu.app.wsgi import WSGIApplication, ControllerBase, route
import logging
import time
import json
from webob import Response

# Name for referencing app instance in WSGI
REST_API_INSTANCE_NAME = 'simple_switch_rest_api_app'

class SimpleSwitch13REST(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Poll interval for stats requests
    POLL_INTERVAL = 5

    # Port scan detection parameters
    PORT_SCAN_THRESHOLD = 10  # More than 10 distinct ports within the window triggers alert
    PORT_SCAN_WINDOW = 10     # 10 seconds

    # DoS detection parameters
    DOS_THRESHOLD = 100       # More than 100 SYN packets in the window triggers a DOS alert
    DOS_WINDOW = 5            # 5 seconds window

    _CONTEXTS = {
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13REST, self).__init__(*args, **kwargs)
        self.logger.setLevel(logging.DEBUG)
        self.mac_to_port = {}
        self.datapaths = {}

        # Data exposed via API
        self.flow_stats_data = {}
        self.port_stats_data = {}

        # Port scan tracking: {src_ip: {"ports": set(), "start_time": t, "detected": bool}}
        self.scan_tracker = {}
        self.scan_alert_count = 0
        self.scan_events = []

        # DOS tracking: {src_ip: {"count": int, "start_time": t, "detected": bool}}
        self.dos_tracker = {}
        self.dos_alert_count = 0
        self.dos_events = []

        # Hosts that have been blocked due to attacks
        self.blocked_hosts = set()

        wsgi = kwargs['wsgi']
        wsgi.register(StatsRestController, {REST_API_INSTANCE_NAME: self})

        # Reset API data on start
        self.reset_api_data()

        # Start periodic stats polling
        self.monitor_thread = hub.spawn(self._monitor)

    def reset_api_data(self):
        """
        Reset all stored API data to ensure endpoints start clean when the controller restarts.
        """
        self.logger.info("Resetting API data to initial state.")
        self.flow_stats_data = {}
        self.port_stats_data = {}
        self.scan_tracker = {}
        self.scan_alert_count = 0
        self.scan_events = []
        self.dos_tracker = {}
        self.dos_alert_count = 0
        self.dos_events = []
        self.blocked_hosts = set()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Install table-miss flow entry and register datapath.
        """
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-miss flow
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Switch %s connected", datapath.id)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, hard_timeout=0, idle_timeout=0):
        """
        Helper function to add a flow entry to the switch.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id is not None:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst,
                                    hard_timeout=hard_timeout, idle_timeout=idle_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    priority=priority,
                                    match=match, instructions=inst,
                                    hard_timeout=hard_timeout, idle_timeout=idle_timeout)
        self.logger.debug("Installing a flow: match=%s, actions=%s", match, actions)
        datapath.send_msg(mod)

    def block_host(self, datapath, src_ip):
        """
        Install a drop flow for traffic from the given source IP to mitigate attacks.
        """
        self.logger.warning("Blocking host %s due to detected attack", src_ip)
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        # No actions => Drop
        actions = []
        # A high priority flow to drop all packets from this IP
        self.add_flow(datapath, priority=100, match=match, actions=actions, hard_timeout=0, idle_timeout=0)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """
        Track switches connected or disconnected.
        """
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info("Register datapath: %s", datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath and datapath.id in self.datapaths:
                self.logger.info("Unregister datapath: %s", datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(self.POLL_INTERVAL)

    def _request_stats(self, datapath):
        """
        Request flow and port stats from datapaths periodically.
        """
        self.logger.debug("Sending stats request to datapath %s", datapath.id)
        parser = datapath.ofproto_parser

        # Flow Stats Request
        flow_req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(flow_req)

        # Port Stats Request
        port_req = parser.OFPPortStatsRequest(datapath, 0, datapath.ofproto.OFPP_ANY)
        datapath.send_msg(port_req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """
        Handler for flow stats reply: store them for the API.
        """
        dpid = ev.msg.datapath.id
        body = ev.msg.body
        flows = []
        for stat in body:
            flow_info = {
                "match": str(stat.match),
                "packet_count": stat.packet_count,
                "byte_count": stat.byte_count,
                "duration_sec": stat.duration_sec,
                "duration_nsec": stat.duration_nsec
            }
            flows.append(flow_info)
        self.flow_stats_data[dpid] = flows

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        """
        Handler for port stats reply: store them for the API.
        """
        dpid = ev.msg.datapath.id
        body = ev.msg.body
        ports = []
        for stat in body:
            port_info = {
                "port_no": stat.port_no,
                "rx_packets": stat.rx_packets,
                "tx_packets": stat.tx_packets,
                "rx_bytes": stat.rx_bytes,
                "tx_bytes": stat.tx_bytes,
                "rx_dropped": stat.rx_dropped,
                "tx_dropped": stat.tx_dropped,
                "rx_errors": stat.rx_errors,
                "tx_errors": stat.tx_errors
            }
            ports.append(port_info)
        self.port_stats_data[dpid] = ports

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Handle Packet-In messages to implement learning switch and detect attacks.
        """
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        dpid = datapath.id
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if not eth_pkt:
            self.logger.debug("Received packet without Ethernet protocol.")
            return

        src = eth_pkt.src
        dst = eth_pkt.dst
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # Just forward as a learning switch for now
        actions = [parser.OFPActionOutput(out_port)]

        # Extract IP/TCP/UDP for detection
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt and ip_pkt.src not in self.blocked_hosts:
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            # We'll not consider UDP for DOS or port scan detection since it can cause victim to appear as attacker.
            
            # Only consider TCP packets with SYN set for both port scan and DoS detection.
            # SYN flag check:
            is_syn = False
            if tcp_pkt and (tcp_pkt.bits & tcp.TCP_SYN):
                is_syn = True

            # Detect DoS only if SYN is set (attacker initiating connections)
            if is_syn:
                self.detect_dos(dpid, ip_pkt.src)

            # Port scan detection also only if SYN:
            if is_syn and tcp_pkt:
                dst_port = tcp_pkt.dst_port
                self.detect_port_scan(dpid, ip_pkt.src, dst_port)

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)

    def detect_port_scan(self, dpid, src_ip, dst_port):
        """
        Detect port scanning behavior based on SYN packets only.
        """
        now = time.time()
        record = self.scan_tracker.get(src_ip, {"ports": set(), "start_time": now, "detected": False})

        # If already detected for this src, return
        if record["detected"]:
            return

        if now - record["start_time"] > self.PORT_SCAN_WINDOW:
            # Reset if window expired
            record["ports"] = set()
            record["start_time"] = now

        record["ports"].add(dst_port)
        self.logger.debug("Port scan check (SYN only): %s hitting ports %s", src_ip, record["ports"])
        self.scan_tracker[src_ip] = record

        if len(record["ports"]) > self.PORT_SCAN_THRESHOLD:
            self.logger.warning("Port scan detected from %s (SYN-based)", src_ip)
            self.scan_alert_count += 1
            self.scan_events.append({
                "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
                "src_ip": src_ip
            })

            # Mark as detected and block
            record["detected"] = True
            self.scan_tracker[src_ip] = record

            self.blocked_hosts.add(src_ip)
            if dpid in self.datapaths:
                self.block_host(self.datapaths[dpid], src_ip)

    def detect_dos(self, dpid, src_ip):
        """
        Detect DoS attacks based on SYN packet count in DOS_WINDOW.
        Only SYN packets are counted to avoid labeling victims (responding with RST/ACK) as attackers.
        """
        now = time.time()
        record = self.dos_tracker.get(src_ip, {"count": 0, "start_time": now, "detected": False})

        # If already detected, return
        if record["detected"]:
            return

        if now - record["start_time"] > self.DOS_WINDOW:
            # Reset if window expired
            record["count"] = 0
            record["start_time"] = now

        record["count"] += 1
        self.dos_tracker[src_ip] = record

        if record["count"] > self.DOS_THRESHOLD:
            self.logger.warning("DoS attack detected from %s", src_ip)
            self.dos_alert_count += 1
            self.dos_events.append({
                "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
                "src_ip": src_ip
            })

            # Mark as detected
            record["detected"] = True
            self.dos_tracker[src_ip] = record

            self.blocked_hosts.add(src_ip)
            if dpid in self.datapaths:
                self.block_host(self.datapaths[dpid], src_ip)


class StatsRestController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(StatsRestController, self).__init__(req, link, data, **config)
        self.simple_switch_app = data[REST_API_INSTANCE_NAME]

    @route('stats', '/stats/flow', methods=['GET'])
    def list_flow_stats(self, req, **kwargs):
        app = self.simple_switch_app
        body = json.dumps(app.flow_stats_data)
        return Response(content_type='application/json; charset=UTF-8', body=body)

    @route('stats', '/stats/port', methods=['GET'])
    def list_port_stats(self, req, **kwargs):
        app = self.simple_switch_app
        body = json.dumps(app.port_stats_data)
        return Response(content_type='application/json; charset=UTF-8', body=body)

    @route('stats', '/stats/scans', methods=['GET'])
    def list_scan_stats(self, req, **kwargs):
        app = self.simple_switch_app
        data = {
            "count": app.scan_alert_count,
            "events": app.scan_events
        }
        body = json.dumps(data)
        return Response(content_type='application/json; charset=UTF-8', body=body)

    @route('stats', '/stats/dos', methods=['GET'])
    def list_dos_stats(self, req, **kwargs):
        app = self.simple_switch_app
        data = {
            "count": app.dos_alert_count,
            "events": app.dos_events
        }
        body = json.dumps(data)
        return Response(content_type='application/json; charset=UTF-8', body=body)
