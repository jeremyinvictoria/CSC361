import dpkt
import socket
import re
import statistics
import sys
def extract_seq(str):
    seq_num=""
    m = re.search("seq=([0-9]+)",str)
    found = m.group(1)
    #seq_num.append(found)
    seq_num=found
    return seq_num
if(len(sys.argv)>2):
    filename = sys.argv[1]
else:
    filename = input("Please enter a filename")
pcap = dpkt.pcap.Reader(open(filename,'rb'))
src_ip_addr=""
dst_ip_addr=""
routers=[]
seq_in_router=[]
ts_in_router=[]

seq_in_src=[]
ts_in_src=[]

protocol = []
for ts,pkt in pcap:
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data

    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        continue
    if ip.p not in protocol:
        protocol.append(ip.p)
    if (ip.p == dpkt.ip.IP_PROTO_ICMP)and(ip.ttl==1):
        src_ip_addr = socket.inet_ntoa(ip.src)
        dst_ip_addr = socket.inet_ntoa(ip.dst)

    if (ip.p == dpkt.ip.IP_PROTO_ICMP):
        icmp = ip.data
        data = repr(icmp.data)
        #sent by source
        #print(data)
        src_addr = socket.inet_ntoa(ip.src)
        dst_addr = socket.inet_ntoa(ip.dst)
        if(src_addr == src_ip_addr):
            seq_num=extract_seq(data)
            seq_in_src.append(seq_num)
            ts_in_src.append(ts)

        #sent by router
        if(dst_addr==src_ip_addr):
            #pass
            routers.append(socket.inet_ntoa(ip.src))
            seq_num = extract_seq(data)
            seq_in_router.append(seq_num)
            ts_in_router.append(ts)
'''compare source seq and router seq, if it's a match, take substraction'''
for i in range(len(seq_in_src)):
    src_seq = seq_in_src[i]
    for j in range(len(seq_in_router)):
        if(src_seq==seq_in_router[j]):
            ts_in_router[j]=ts_in_router[j] - ts_in_src[i]
#print(ts_in_router)
ip_dir={}
for i in range(len(routers)):
    if routers[i] not in ip_dir.keys():
        ip_dir[routers[i]]=[]
        #ip_dir[new_ip_addr[i]].append(new_rrt[i])
    if routers[i] in ip_dir.keys():
        ip_dir[routers[i]].append(ts_in_router[i])
#print(protocol)
new_routers=[]
for i in routers:
    if i not in new_routers:
        new_routers.append(i)
print("The IP address of the source node: "+str(src_ip_addr))
print("The IP address of ultimate destination node: "+str(dst_ip_addr))
print("The IP addresses of the intermediate destination nodes:")
for i in range(len(new_routers)):
    if new_routers[i]!=dst_ip_addr:
        print("\trouter "+str(i+1)+": "+str(new_routers[i]))
print("The values in the protocol field of IP headers:")
for i in range(len(protocol)):
    if(protocol[i]==1):
        print(str(1)+": "+"ICMP")
    if(protocol[i]==17):
        print(str(17) + ": " + "UDP")
    if(protocol[i]==6):
        print(str(6) + ": " + "TCP")
for key,value in ip_dir.items():
    if(len(value)>1):
        print("The avg RRT between "+src_ip_addr+" and "+ key+" is: "+str(statistics.mean(value))+", the s.d is: "+str(statistics.stdev(value)))
    else:
        #print(key+"average RRT is:"+str(statistics.mean(value))+" s.d is: "+str(0))
        print("The avg RRT between "+src_ip_addr+" and "+ key+" is: "+str(statistics.mean(value))+", the s.d is: "+str(0))
