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
import sys

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '
sourceIpv4 = {''}

class frameHeader:
    ipsourc = str()
    ipdesti = str()
    time = str()
    count = int()

def AddtoFrame(ipsource, ipdesti, count):
    Frame = frameHeader
    Frame.ipsourc = ipsource
    Frame.ipdesti = ipdesti
    Frame.time = datetime.datetime.now().strftime("%H%M%S")
    Frame.count = count
    return Frame

def count():
    sys.stdout.write('hala')
#Xuat data Ethernet
def printSniffer(eth,count):
    #sys.stdout.write('\nEthernet Frame:')
    #sys.stdout.write(count.__str__() + '\t'+'ThisisTime' +'\t'+ eth.src_mac.__str__()+'\t'+eth.dest_mac)
    #sys.stdout.write(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(eth.dest_mac, eth.src_mac, eth.proto))

    # IPv4
    if eth.proto == 8:
        #sys.stdout.write(TAB_1 + 'ethproto=8')
        ipv4 = IPv4(eth.data)
        ipv4src = ipv4.src.__str__()
        ipv4target = ipv4.target.__str__()
        #sys.stdout.write(TAB_1 + 'IPv4 Packet:' + TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4.version, ipv4.header_length, ipv4.ttl))
        #sys.stdout.write(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))
        #sys.stdout.write(count.__str__() + '\t' + 'Timeeeee' + '\t' + ipv4.src.__str__() + '\t' + ipv4.target.__str__() +'\t'+ipv4.proto.__str__()+'\t'+ipv4.header_length.__str__()+'\tInfo')
        # ICMP
        if ipv4.proto == 1:
            #sys.stdout.write(TAB_1 + 'ethproto=1')
            icmp = ICMP(ipv4.data)
            #sys.stdout.write(TAB_1 + 'ICMP Packet:')
            #sys.stdout.write(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp.type, icmp.code, icmp.checksum))
            icmpinfo = 'Type:'+icmp.type.__str__() +'Code'+ icmp.code.__str__() +'Checksum'+ icmp.checksum.__str__()
            #sys.stdout.write(TAB_2 + 'ICMP Data:')
            sys.stdout.write('{0:5}\t{1:8}\t{2:15}\t{3:15}\t{4:8}\t{5:6}\t\t'.format(count.__str__(),"Timeeeee",ipv4.src, ipv4.target,'ICMP',len(icmp.data).__str__(),icmpinfo))

            #sys.stdout.write(format_multi_line(DATA_TAB_3, icmp.data))

        # TCP
        elif ipv4.proto == 6:
            #sys.stdout.write(TAB_1 + 'ethproto=6')
            tcp = TCP(ipv4.data)
            #sys.stdout.write(TAB_1 + 'TCP Segment:')
            #sys.stdout.write(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
            #sys.stdout.write(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
            #sys.stdout.write(TAB_2 + 'Flags:')
            #sys.stdout.write(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
            #sys.stdout.write(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))
            tcpinfo = 'SrcPort:{}, DestPort:{}'.format(tcp.src_port, tcp.dest_port) + ' Sequence:{}, Acknowledgment:{}'.format(tcp.sequence, tcp.acknowledgment) + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh) + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin)
            '''
            if len(tcp.data) > 0:
            
                #HTTP
                if tcp.src_port == 80 or tcp.dest_port == 80:
                    sys.stdout.write(TAB_2 + 'HTTP Data:')
                    try:
                        http = HTTP(tcp.data)
                        http_info = str(http.data).split('\n')
                        for line in http_info:
                            sys.stdout.write(DATA_TAB_3 + str(line))
                    except:
                        sys.stdout.write(format_multi_line(DATA_TAB_3, tcp.data))
                else:
                    sys.stdout.write(TAB_2 + 'TCP Data:')
                    #sys.stdout.write(format_multi_line(DATA_TAB_3, tcp.data))
            '''
            sys.stdout.write('{0:5}\t{1:8}\t{2:15}\t{3:15}\t{4:8}\t{5:6}\t\t'.format(count,'Timeeeee',ipv4.src, ipv4.target,'TCP',len(tcp.data),tcpinfo))
        # UDP
        elif ipv4.proto == 17:
            #sys.stdout.write(TAB_1 + 'ethproto=17')
            udp = UDP(ipv4.data)
            udpinfo = 'SrcPort: {}, DestPort:{}, Length'.format(udp.src_port, udp.dest_port,udp.size)
            #sys.stdout.write(TAB_1 + 'UDP Segment:')
            #sys.stdout.write(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port, udp.dest_port,udp.size))
            sys.stdout.write('{0:5}\t{1:8}\t{2:15}\t{3:15}\t{4:8}\t{5:6}\t\t'.format(count,"Timeeeee",ipv4.src, ipv4.target,'UDP',len(udp.data),udpinfo))
        # Other IPv4
        else:
            sys.stdout.write(TAB_1 + 'ethproto=conlai')
            sys.stdout.write(TAB_1 + 'Other IPv4 Data:')
            sys.stdout.write(format_multi_line(DATA_TAB_2, ipv4.data))

    else:
        sys.stdout.write('Ethernet Data: = Protocol != 8  {}'.format(eth.proto))
        # sys.stdout.write(format_multi_line(DATA_TAB_1, eth.data))
#Luu du lieu data_raw vao pcap

def checkSniffer(eth):
    sys.stdout.write('\nEthernet Frame:')
    FrameEth = list()
    # IPv4
    if eth.proto == 8:
        ipv4 = IPv4(eth.data)
        FrameEth.append(AddtoFrame(str(ipv4.src), str(ipv4.target), 1))
        sys.stdout.write("Ip Source: " + FrameEth[0].ipsourc,"Ip Target: " + FrameEth[0].ipdesti, "Time: " + FrameEth[0].time)
    else:
        sys.stdout.write('Ethernet Data: = Protocol != 8' + str(eth.proto))
def sniffer():
    str = 'capture'+datetime.datetime.now().strftime("%d%m%Y_%H%M%S")
    pcap = Pcap('Capture/'+str+'.pcap')
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    sys.stdout.write('{0:5}\t{1:8}\t{2:15}\t{3:15}\t{4:8}\t{5:6}\t\t{6}'.format('No','Time','Source','Destination','Protocol','Length','Info'))
    _count = 1
    while True:
        raw_data, addr = conn.recvfrom(65535)
        pcap.write(raw_data)
        ethernetdata = Ethernet(raw_data)
        printSniffer(ethernetdata,_count)
        _count += 1

        #checkSniffer(ethernetdata)
    pcap.close()
def main():
    sniffer()

main()
