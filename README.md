POX_Firewall
============

Team 5 - Ben Boren, Erin Lanus, Matt Welch

Firewall.py implements firewall-like functionality for POX. The code uses
of_tutorial.py (Copyright 2012 James McCauley) as a skeleton. When a switch
connects to the controller, the component initializes the connection to the
switch as well as adding low-priority flow entries  to allow certain types of
packets to pass through (i.e. ICMP, IP, ARP), but block all TCP packets that
are not specified by a rule in the firewall configuration file. It pushes
medium priority flow entries for rules from the configuration file. When it
receives a packet, it checks the configuration rules to ensure that there is a
match, then pushes symmetric flow entries from the packet specifics.  If there
is not a match, it pushes a flow entry with null action, so the switch will
drop packets from that flow.

Instructions
------------
Open a terminal and launch mininet with the tested topology:

	$ sudo mn --custom ~/path/to/mininettopo.py --topo mytopo --mac --switch ovsk --controller remote

Run the IP configuration script inside mininet to set up IP addresses of hosts

	mininet> py execfile("/path/to/config.py")

Open another terminal, navigate to the pox directory and launch the POX
controller with the Firewall module:

	$ ./pox.py log.level --DEBUG misc.Firewall --configuration="/path/to/mininet_firewall.config"

Once mininet has launched and the firewall is running, you can test the
connectivity.  In mininet, launch an xterm for hosts:

	mininet> xterm host9
	mininet> xterm host1

Open an xterm for the switch so that the flows can be observed:

	mininet> xterm s3

In the switch, set up a watch on the flow list with a 1 second interval

	root@mininet:~# watch -n 1 sudo ovx-ofctl dump-flows s3

In this example, host9 will open an xterm window and will have th IP address of
10.10.10.14/24.  Host1 will open with IP address 10.10.10.6/24.  Note, these
hosts were chosen because they match a firewall rule in mininet_firewall.config.

Set up a netcat listener on host9 at port 6666

	root@mininet:~# nc -l 6666

From Host1, connect to the netcat listener at host9, port 6666

	root@mininet:~# nc 10.10.10.14 6666

You should see flows added to the flow list on the switch output and status
messages in the controller.

Design Methodology
------------------
The design of the firewall can be summarized as follows.  The controller
proactively loads a set of rules onto the switch to act as a primary filter on
incoming packets.  Only packets matching rules on the switch are then forwarded
to the controller which installs bidirectional flows on the switch to enable
that traffic.  This design requires the switch to handle the majority of
traffic as it should and only send data to the controller as necessary.  This
should allow the controller to scale to control a larger number of switches and
the corresponding increase in new flows.

Detailed Algorithm Description
------------------------------
1)	On startup, the controller reads the configuration rules specified on the
command line into memory and listens for a switch to connect on the default
port 6633.

2) 	Once a switch has connected, the controller loads rules onto the switch to
allow ICMP and ARP packets to pass through unimpeded.  It also installs rules
that instruct the switch to forward packets matching the configuration file
rules to the controller for further consideration. These rules should be of the
form:

	<ip> [ / <netmask> ] <port> <ip> [ / <netmask> ] <port>

where any of the IP or port fields may be replaced with the wildcard 'any' and
all fields are separated by a single space.  The configuration file is further
detailed in Firewall.py.
The final rule installed to the switch on the initial phase	instructs the
switch to drop all TCP packets that do not match the previous rules. These are
specified by a rule with no action.
Before the rules are sent to the switch, they are further conditioned so that
any rule that contains a non-zero host IP and subnet mask in CIDR notation is
stripped of the subnet mask and sent as a source IP only.  This is because POX
expects only a host IP without netmask or network IP address with netmask and
will cause an exception if a rule is set with an IP address containing a non-
zero host IP and netmask.  The choice when reading these rules is thus to drop
the host portion of the IP address or drop the netmask.  It was decided that
masking off the host portion in favor of keeping the netmask would result in a
more general rule than was intended which is in conflict with the principles of
a secure firewall.  If the subnet rule is desired, it should be specified as a
network address only with a host address of zero.

3)	After the proactive rule set has been sent to the switch, the switch waits
for incoming connections that match its rule set and forwards those matching
packets to the controller as appropriate.

4)	When the controller receives encapsulated packets from the switch, these
packets are compared against the rule set for debugging purposes.  These
packets should be allowed flows since they have already made it past the
primary filtering by the switch.  Packets are matched with a configuration rule
and a bidirectional (symmetric) pair of flows is installed to allow TCP traffic
between the originating source host and its intended destination host.  The
encapsulated packet representing the flow is also returned to the switch for
forwarding to its intended destination.  If the encapsulated packet does not
match the rule set, it is dropped.
