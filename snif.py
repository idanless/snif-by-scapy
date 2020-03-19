import time
from scapy.all import *

def pkt_callback(pkt):
    if pkt[TCP].payload:
        #full payload + ip + port as print
        print (pkt[IP].src,pkt[TCP].dport,'\n' ,pkt[TCP].payload)
    #debug print
    #print(pkt.show2()) # debug statement

#interface + filter
sniff(iface="eno1", prn=pkt_callback, filter="tcp and port 80", store=0)
