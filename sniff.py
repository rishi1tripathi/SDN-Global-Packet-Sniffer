import argparse
from scapy.all import *
import datetime

parser=argparse.ArgumentParser(description="Python3 based sniffer application writes output to a file, supports following option")
parser.add_argument('--iface',help="comma(,) seperated interface names, if not provided default interface is selected")
parser.add_argument('--file','-f',help="filename to store captured packets, else a new file will be created, captures will be appended if file already exists")
parser.add_argument('--proto',help="comma(,) seperated list of upto l4 protocols to filter capture, default(IP and ARP)")
parser.add_argument('--count','-c',type=int,default=0,help="number of packets to capture, default 0(no limit)")
args=parser.parse_args().__dict__

if args['file'] is None:
    fileName=datetime.datetime.now().strftime('%Y%m%d%H%M%S')+'.pcap'
else:
    fileName=args['file']

if args['iface'] is not None:
    src_interfaces=args['iface'].split(',')
else:
    src_interfaces=conf.iface


if args['proto'] is None:
    proto_filter='ip or arp'
else:
    proto_filter=' or '.join([x.lower() for x in args['proto'].split(',')])

packet_count=args['count']

print("Capture will be saved in:",fileName)
print("Capturing packets from:",src_interfaces)
print("Protocols to filter upon:",proto_filter)
if packet_count==0:
    print("Number of packets to capture:",packet_count,"(no limit)")
else:
    print("Number of packets to capture:",packet_count)
print("********************Capturing packets*********************")

def process_pkt(pkt):
    wrpcap(fileName,pkt,append=True)

sniff(iface=src_interfaces, prn=process_pkt, count=packet_count, filter=proto_filter)