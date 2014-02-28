POX_Firewall
============

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

Instructions
------------
Open a terminal and launch mininet with the tested topology:

	$ sudo mn --custom ~/path/to/mininettopo.py --topo mytopo --mac --switch ovsk --controller remote

Run the IP configuration script inside mininet to set up IP addresses of hosts

	mininet> py execfile("/path/to/config.py")1

Open another terminal, navigate to the pox directory and launch the POX controller with the Firewall module:

	$ ./pox.py log.level --DEBUG misc.Firewall --configuration="/path/to/mininet_firewall.config"

Once mininet has launched and the firewall is running, you can test the connectivity.
In mininet, launch an xterm for hosts:

	mininet> xterm host9
	mininet> xterm host1

Open an xterm for the switch so that the flows can be observed:

	mininet> xterm s3

In the switch, set up a watch on the flow list with a 1 second interval

	root@mininet:~# watch -n 1 sudo ovx-ofctl dump-flows s3

In this example, host9 will open an xterm window and will have th IP address of 10.10.10.14/24.
Host1 will open with IPI address 10.10.10.6/24.  Note, these hosts were chosed because they match
a firewall rule in mininer_firewall.config.

Set up a netcat listener on host9 at port 6666

	root@mininet:~# nc -l 6666

From Host1, connect to the netcat listener at host9, port 6666

	root@mininet:~# nc 10.10.10.14 6666

You should see flows added to the flow list on the switch output and status messages in the controller.

Some advanced options
---------------------

Design Methodology
------------------

