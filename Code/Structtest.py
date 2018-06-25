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
        if(_frameHeader[i].ipsourc == ipsource and _frameHeader[i].ipdesti == ipdesti):
            return i
    return -1


def AddtoFrame(_frameHeader, ipsource, ipdesti, count):
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
        #print(searchforframe(_frameHeader,"192.168.10.2","192.168.10.2"))"""
def printFrame(_frameHeader):
    for i in range(0,len(_frameHeader)):
        print(_frameHeader[i].ipsourc.__str__() +" "+_frameHeader[i].ipdesti.__str__()+" "+_frameHeader[i].count.__str__())
def count():
    print('hala')
def RefreshlistFrame(_listFrame):
    for i in range(0,len(_listFrame)-1):
        if _listFrame[i].time == 1:
            return
# Xuat data Ethernet
def checkSniffer(eth,_listFrameEth):
    print('\nEthernet Frame:')
    # IPv4
    if eth.proto == 8:
        ipv4 = IPv4(eth.data)
        AddtoFrame(_listFrameEth, ipv4.src, ipv4.target, 1)
        #print(_listFrameEth[len(_listFrameEth)-1].ipsourc,_listFrameEth[len(_listFrameEth)-1].ipdesti, _listFrameEth[len(_listFrameEth)-1].count,_listFrameEth[len(_listFrameEth)-1].time)
    #else:
        #print('Ethernet Data: = Protocol != 8' + str(eth.proto))
    printFrame(_listFrameEth)
# Luu du lieu data_raw vao pcap
def sniffer():
    str = 'capture' + datetime.datetime.now().strftime("%d%m%Y_%H%M%S")
    pcap = Pcap('Capture/' + str + '.pcap')
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    listFrame = []
    while True:
        raw_data, addr = conn.recvfrom(65535)
        pcap.write(raw_data)
        ethernetdata = Ethernet(raw_data)
        checkSniffer(ethernetdata,listFrame)
    pcap.close()


def main():
    sniffer()
main()