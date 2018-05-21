import socket
import datetime
from general import *
from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.icmp import ICMP
from networking.tcp import TCP
from networking.udp import UDP
from networking.pcap import Pcap
from networking.http import HTTP


class frameHeader:
    ipsourc = str()
    ipdesti = str()
    time = str()
    count = int()


TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '
sourceIpv4 = {''}


def searchforframe(_frameHeader, ipsource, ipdesti):
    for i in range(0,len(_frameHeader)):
        if(_frameHeader[i].ipsourc ==ipsource and _frameHeader[i].ipdesti ==ipdesti):
            return i
    return -1

def AddtoFrame(_frameHeader, ipsource, ipdesti, count):
    #print(searchforframe(_frameHeader, ipsource, ipdesti), len(_frameHeader))
    if (searchforframe(_frameHeader, ipsource, ipdesti ) == -1):
        #print("Them moi vao")
        Frame = frameHeader()
        Frame.ipsourc = ipsource
        Frame.ipdesti = ipdesti
        Frame.time = datetime.datetime.now().strftime("%H%M%S")
        Frame.count = count
        _frameHeader.append(Frame)
    else:
        #print("Chinh sua moi vao")
        _frameHeader[searchforframe(_frameHeader, ipsource, ipdesti)].count += 1

def count():
    print('hala')

# Xuat data Ethernet
def checkSniffer(eth):
    print('\nEthernet Frame:')
    FrameEth = []
    # IPv4
    if eth.proto == 8:
        ipv4 = IPv4(eth.data)
        AddtoFrame(FrameEth, ipv4.src, ipv4.target, 1)
        print(FrameEth[len(FrameEth)-1].ipsourc,FrameEth[len(FrameEth)-1].ipdesti, FrameEth[len(FrameEth)-1].count,FrameEth[len(FrameEth)-1].time)
    #else:
        #print('Ethernet Data: = Protocol != 8' + str(eth.proto))
# Luu du lieu data_raw vao pcap
def sniffer():
    str = 'capture' + datetime.datetime.now().strftime("%d%m%Y_%H%M%S")
    pcap = Pcap('Capture/' + str + '.pcap')
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = conn.recvfrom(65535)
        pcap.write(raw_data)
        ethernetdata = Ethernet(raw_data)
        checkSniffer(ethernetdata)
    pcap.close()


def main():
    sniffer()
main()