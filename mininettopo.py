from mininet.topo import Topo

class MyTopo( Topo ):
    

    def __init__( self ):
        

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        Host1 = self.addHost( 'host1' )
	Host2 = self.addHost( 'host2' )
	Host3 = self.addHost( 'host3' )
	Host4 = self.addHost( 'host4' )
	Host5 = self.addHost( 'host5' )
	Host6 = self.addHost( 'host6' )
	Host7 = self.addHost( 'host7' )
	Host8 = self.addHost( 'host8' )
	Host9 = self.addHost( 'host9' )
	Server1 = self.addHost( 'server1' )
	Server2 = self.addHost( 'server2' )
	Server3 = self.addHost( 'server3' )
	Server4 = self.addHost( 'server4' )
	Server5 = self.addHost( 'server5' )
		
        Switch = self.addSwitch( 's3' )
        

        # Add links
        self.addLink( Host1, Switch )
	self.addLink( Host2, Switch )
	self.addLink( Host3, Switch )
	self.addLink( Host4, Switch )
	self.addLink( Host5, Switch )
	self.addLink( Host6, Switch )
	self.addLink( Host7, Switch )
	self.addLink( Host8, Switch )
	self.addLink( Host9, Switch )
	self.addLink( Server1, Switch )
	self.addLink( Server2, Switch )
	self.addLink( Server3, Switch )
	self.addLink( Server4, Switch )
	self.addLink( Server5, Switch )

topos = { 'mytopo': ( lambda: MyTopo() ) }
