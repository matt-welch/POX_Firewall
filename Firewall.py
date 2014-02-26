"""
Team 5 - Ben Boren, Erin Lanus, Matt Welch
Firewall.py implements firewall-like functionality for POX. The code uses
of_tutorial.py (Copyright 2012 James McCauley) as a skeleton. When a switch
connects to the controller, the component initializes the connection to the
switch as well as adding low-priority flow entries  to allow certain types
of packets to pass through (i.e. ICMP, IP, ARP), but block all TCP packets
that are not specified by a rule in the firewall configuration file. It
pushes medium priority flow entries for rules from the configuration file.
When it receives a packet, it checks the configuration rules to ensure that
there is a match, then pushes symmetric flow entries from the packet specifics.
If there is not a match, it pushes a flow entry with null action, so the switch
will drop packets from that flow.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
#import pox.lib.packet.packet_base
#import pox.lib.packet.packet_utils
import pox.lib.packet as pkt
log = core.getLogger()



class Firewall (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """

  def __init__ (self, connection):

    def setupProtocolFlow (self, nw_proto, dl_type):
        msg = of.ofp_flow_mod()
        match = of.ofp_match()
        match.nw_src = None
        match.nw_dst = None
        match.tp_src = None
        match.tp_dst = None
        match.nw_proto = nw_proto # 1 for ICMP or ARP opcode
        match.dl_type = dl_type # == 0x0800 for IP, 0x0806 for ARP
        msg.match = match
        msg.hard_timeout = 0
        msg.soft_timeout = 0
        msg.priority = 32768
        action = of.ofp_action_output(port = of.OFPP_NORMAL)
        msg.actions.append(action)
        if (VERBOSEMODE):
            print "Inserting flow for: " + msg.__str__()
        self.connection.send(msg)


    global config
    if DEBUGMODE is True:
        print config
    if VERBOSEMODE:
        print ("__init__()")
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port = {}

    # establish base rules for ICMP, ARP, and dropping unknown packets
    if(DEBUGMODE):
        print "Inserting icmp packet flow"
    # add rule to allow ALL ICMP packets
    setupProtocolFlow(self, pkt.ipv4.ICMP_PROTOCOL, pkt.ethernet.IP_TYPE)

    if(DEBUGMODE):
        print "Inserting arp packet flows"
    # add rule to allow ALL ARP packets
    setupProtocolFlow(self, pkt.arp.REQUEST, pkt.ethernet.ARP_TYPE)
    setupProtocolFlow(self, pkt.arp.REPLY, pkt.ethernet.ARP_TYPE)
    setupProtocolFlow(self, pkt.arp.REV_REQUEST, pkt.ethernet.ARP_TYPE)
    setupProtocolFlow(self, pkt.arp.REV_REPLY, pkt.ethernet.ARP_TYPE)

    # add rule to drop all packets not defined by another rule
    msg = of.ofp_flow_mod()
    match = of.ofp_match()
    msg.match = match
    msg.hard_timeout = 0
    msg.soft_timeout = 0
    msg.priority = 1

    if(DEBUGMODE):
        print "Inserting drop packet flow"
    if (VERBOSEMODE):
        print "Inserting flow for drop packets: " + msg.__str__()
    self.connection.send(msg)

    priority = 32768 # 0x8000, the default priority
    # Insert flows from config list
    # these rules allow the specified hosts to establish flows that match on the addresses and wildcards
    for rule in config:
        msg = of.ofp_flow_mod()
        match = of.ofp_match()
	# Check for malformed IP address
	rule[srcIP] = check_ip(rule[srcIP])
	rule[dstIP] = check_ip(rule[dstIP])
        if rule[srcIP] != 'any':
            match.nw_src = rule[srcIP]
        else:
            match.nw_src = None
        if rule[dstIP] != 'any':
            match.nw_dst = rule[dstIP]
        else:
            match.nw_dst = None
        if rule[srcPort] != 'any':
            match.tp_src = int(rule[srcPort]) # must convert the string to an int??
        else:
            match.tp_src = None
        if rule[dstPort] != "any":
            match.tp_dst = int(rule[dstPort]) # must convert the string to an int??
        else:
            match.tp_dst = None
        # specify the IP protocol or lower 8 bits of ARP opcode
        # all packets to match on are TCP
        match.nw_proto = pkt.ipv4.TCP_PROTOCOL # == 6
        # specify all packets as IP
        match.dl_type = pkt.ethernet.IP_TYPE # == 0x0800
        msg.match = match
        msg.hard_timeout = 0
        msg.soft_timeout = 0
        msg.priority = priority
        action = of.ofp_action_output(port = of.OFPP_CONTROLLER)
        msg.actions.append(action)
        if (VERBOSEMODE):
            print "Inserting flow for: " + msg.__str__()
        self.connection.send(msg)



  def resend_packet (self, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    if VERBOSEMODE:
        print "resend_packet()"
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)


  def check_config (self, fields):
    if VERBOSEMODE:
        print "check_config()"
    print fields
    global config, srcIP, srcPort, dstIP, dstPort
    flag = False
    for rule in config:
      if fields[srcIP] == rule[srcIP] or rule[srcIP] == 'any':
        if fields[srcPort] == rule[srcPort] or rule[srcPort] == 'any':
          if fields[dstIP] == rule[dstIP] or rule[dstIP] == 'any':
            if fields[dstPort] == rule[dstPort] or rule[dstPort] == 'any':
              print rule
              flag = True
              break
    return flag

  def installSymmetricFlow (self, packet, packet_in, allowed):
    def installFlow (self, nw_src, nw_dst, tp_src, tp_dst, allowed):
        msg = of.ofp_flow_mod()
        match = of.ofp_match()
        match.nw_src = nw_src
        match.nw_dst = nw_dst
        match.tp_src = int(tp_src)
        match.tp_dst = int(tp_dst)
        # all packets to match on are TCP
        match.nw_proto = pkt.ipv4.TCP_PROTOCOL # == 6
        # specify all packets as IP
        match.dl_type = pkt.ethernet.IP_TYPE # == 0x0800
        msg.match = match
        msg.hard_timeout = 0
        msg.idle_timeout = 180 # previously known as soft_timeout
        msg.priority = 49152
        if allowed:
            action = of.ofp_action_output(port = of.OFPP_NORMAL)
            msg.actions.append(action)
        if (VERBOSEMODE):
          print "Inserting flow for: " + msg.__str__()
        self.connection.send(msg)

    # get the IP packet from the payload
    ip_packet = packet.payload

    # get the TCP packet from the IP packet
    tcp_packet = ip_packet.payload
    #fields = [str(ip_packet.srcip), str(tcp_packet.srcport), str(ip_packet.dstip), str(tcp_packet.dstport)]

    # send a message to the switch to install the forward flow
    installFlow(self, ip_packet.srcip, ip_packet.dstip, tcp_packet.srcport, tcp_packet.dstport, allowed)

    # send a message to the switch to install the reverse flow
    installFlow(self, ip_packet.dstip, ip_packet.srcip, tcp_packet.dstport, tcp_packet.srcport, allowed)

  def act_like_firewall (self, packet, packet_in):
    """
    Implement firewall-like behavior.
    packet.src is (ethernet) source IP, packet.dst is (ethernet) dest IP
    packet_in.in_port is switch port it arrived on
    """
    if(VERBOSEMODE):
        print "act_like_switch()"
    print "Packet Type: ", packet.type
#    if packet.type == packet.ARP_TYPE:
#      print "ARP"
    if packet.type == packet.IP_TYPE:
      ip_packet = packet.payload
      if ip_packet.protocol == ip_packet.TCP_PROTOCOL:
        tcp_packet = ip_packet.payload
        fields = [str(ip_packet.srcip), str(tcp_packet.srcport), str(ip_packet.dstip), str(tcp_packet.dstport)]
	# this doesn't necessarily need to check the config since these packets have already been filtered by the switch
    if Firewall.check_config(self, fields):
        allowed = True
    else:
        allowed = False
    # TODO filter out 'icmpv6' packets - causes error  "AttributeError: 'icmpv6' object has no attribute 'srcport'"
    # install symmetric flows for the source and destination of the packet
    Firewall.installSymmetricFlow(self, packet, packet_in, allowed)

    '''
    # Learn the port for the source MAC
    self.mac_to_port[packet.src] = packet_in.in_port
    if DEBUGMODE:
        print self.mac_to_port


    if packet.dst in self.mac_to_port: # the port associated with the destination MAC of the packet is known:
        # Send packet out the associated port
      self.resend_packet(packet_in, self.mac_to_port[packet.dst])

      log.debug("Installing flow...from " + str(packet.src) + ", " + str(packet_in.in_port) + " to " + str(packet.dst) + ", " +  str(self.mac_to_port[packet.dst]))

      msg = of.ofp_flow_mod()

      # Set fields to match received packet
      msg.match = of.ofp_match.from_packet(packet)

      #< Set other fields of flow_mod (timeouts? buffer_id?) >
      msg.idle_timeout = 180
      msg.hard_timeout = 0
      msg.match.buffer_id = packet_in.buffer_id
      #< Add an output action, and send -- similar to resend_packet() >
      action = of.ofp_action_output(port = self.mac_to_port[packet.dst])
      msg.actions.append(action)
      self.connection.send(msg)
    else:
      # Flood the packet out everything but the input port
      # This part looks familiar, right?
      if DEBUGMODE:
          print "Broadcasting packet on switches"
      self.resend_packet(packet_in, of.OFPP_ALL)
    '''

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    if VERBOSEMODE:
      print "_handle_PacketIn()"
    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return
    packet_in = event.ofp # The actual ofp_packet_in message.
    self.act_like_firewall(packet, packet_in)


def parse_config(configuration):
  if VERBOSEMODE:
      print "parse_config()"
  global config
  fin = open(configuration)
  for line in fin:
    rule = line.split()
    if (len(rule) > 0) : # only make a rule if the line is not empty
        config.append(rule)
  if (False):
    print config


def check_ip (addr):
  """
  Takes an address if the address is in cidr notation and contains a host then the cidr 
  portion is stripped from the address

  FIXME: This function is badly named.
  """
  if VERBOSEMODE:
    print "check_ip()"
  s_addr = addr.split('/', 2)
  if len(s_addr) == 1:
	return addr
  a = IPAddr(s_addr[0]).toUnsigned()
  hm = 32-int(s_addr[1])
  h = a & ((1<<hm)-1)  
  if (hm == 0):
	return addr
  else:
	return s_addr[0]

# to call, misc.of_tutorial --configuration=<path to config file>
def launch (configuration=""):
  """
  Starts the component
  """
  if VERBOSEMODE:
      print "launch()"
  parse_config(configuration) #calls parseconfig method and passes string from command line

  def start_switch (event):
    if  VERBOSEMODE:
        print("start_switch()")
    log.debug("Controlling %s" % (event.connection,))
    Firewall(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)


config = [] #declaring it here puts it in the "main" frame so it can be referred to globally
# like macros for the config list config[0][src] gets you the src for the 1st rule, etc.
srcIP = 0
srcPort = 1
dstIP = 2
dstPort = 3

DEBUGMODE=True # controls printing output like the parse_config output, etc.
VERBOSEMODE=True # controls printing of the function names when they are called

