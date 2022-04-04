#!/usr/bin/python
import sys
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import OVSSwitch, Controller, RemoteController


class SingleSwitchTopo(Topo):

    def build(self):
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')

        a1 = self.addHost('a1')
        b1 = self.addHost('b1')
        c1 = self.addHost('c1')
        d1 = self.addHost('d1')
        sniffer = self.addHost('sniffer')

        self.addLink(s1, a1)
        self.addLink(s2, b1)
        self.addLink(s2, d1)
        self.addLink(s3, c1)
        self.addLink(s4, sniffer)

        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s3, s4)


if __name__ == '__main__':
    setLogLevel('info')
    topo = SingleSwitchTopo()
    c1 = RemoteController('c1', ip=sys.argv[1])
    net = Mininet(topo=topo, controller=c1)
    net.start()
    CLI(net)
    net.stop()