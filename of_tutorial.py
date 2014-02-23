# Copyright 2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This component is for use with the OpenFlow tutorial.

It acts as a simple hub, but can be modified to act like an L2
learning switch.

It's roughly similar to the one Brandon Heller did for NOX.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
#import pox.lib.packet.packet_base
#import pox.lib.packet.packet_utils
import pox.lib.packet as pkt
log = core.getLogger()



class Tutorial (object):
  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """

  def __init__ (self, connection):
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

    # Insert flows from config list
    #global config
    for rule in config:
        msg = of.ofp_flow_mod()
        match = of.ofp_match()
        if rule[srcIP] != 'any':
            match.nw_src = rule[srcIP]
        else:
            match.nw_src = None
        if rule[dstIP] != 'any':
            match.nw_dst = rule[dstIP]
        else:
            match.nw_dst = None
        if rule[srcPort] != 'any':
            match.tp_src = rule[srcPort]
        else:
            match.tp_src = None
        if rule[dstPort] != "any":
            match.tp_dst = rule[dstPort]
        else:
            match.tp_dst = None
        msg.match = match
        msg.hard_timeout = 0
        msg.priority = 2
        action = of.ofp_action_output(port = of.OFPP_CONTROLLER)
        msg.actions.append(action)
        self.connection. send(msg)



  def resend_packet (self, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    if VERBOSEMODE:
        print "resend_packet"
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


  def act_like_switch (self, packet, packet_in):
    """
    Implement switch-like behavior.
    packet.src is (ethernet) source IP, packet.dst is (ethernet) dest IP
    packet_in.in_port is switch port it arrived on
    """
    if(VERBOSEMODE):
        print "act_like_switch()"
    print "Packet Type: ", packet.type
    if packet.type == packet.ARP_TYPE:
      print "ARP"
    if packet.type == packet.IP_TYPE:
      ip_packet = packet.payload
      if ip_packet.protocol == ip_packet.TCP_PROTOCOL:
        tcp_packet = ip_packet.payload
        fields = [str(ip_packet.srcip), str(tcp_packet.srcport), str(ip_packet.dstip), str(tcp_packet.dstport)]
	if Tutorial.check_config(self, fields):
          allowed = True
        else:
          allowed = False


    # Learn the port for the source MAC
    self.mac_to_port[packet.src] = packet_in.in_port


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
      self.resend_packet(packet_in, of.OFPP_ALL)



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
    self.act_like_switch(packet, packet_in)


def parse_config(configuration):
  if VERBOSEMODE:
      print "parse_config()"
  global config
  fin = open(configuration)
  for line in fin:
    rule = line.split()
    config.append(rule)
  if (False):
    print config

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
    Tutorial(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)


config = [] #declaring it here puts it in the "main" frame so it can be referred to globally
# like macros for the config list config[0][src] gets you the src for the 1st rule, etc.
srcIP = 0
srcPort = 1
dstIP = 2
dstPort = 3

DEBUGMODE=True # controls printing output like the parse_config output, etc.
VERBOSEMODE=True # controls printing of the function names when they are called

