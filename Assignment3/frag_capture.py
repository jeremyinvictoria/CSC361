import dpkt
import socket
import re
import statistics
import sys
if(len(sys.argv)>2):
    filename = sys.argv[1]
else:
    filename = input("Please enter a filename")
#filename = "frag_test.pcap"
pcap = dpkt.pcap.Reader(open(filename,'rb'))
fragment_count=1
router=[]
udp_count=0
offset_of_last_fragment=0
previous_id=[]
for ts, pkt in pcap:
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data
    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        continue
    if (ip.p == dpkt.ip.IP_PROTO_UDP) and (ip.ttl == 1):
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        if(more_fragments==1):
            udp = ip.data
            #print(udp.sport)
            #print(udp.dport)
            #src_ip_addr = socket.inet_ntoa(ip.src)
            #dst_ip_addr = socket.inet_ntoa(ip.dst)
            #print("src: "+str(src_ip_addr)+" dst: "+str(dst_ip_addr)+" MF: "+str(more_fragments))
            #print("id is: "+str(ip.id))
            #if(more_fragments==1):
            previous_id.append(ip.id)
            #print(more_fragments)
        else:
            if ip.id in previous_id:
                offset_of_last_fragment = ip.offset
                #print(offset_of_last_fragment)
    if (ip.p == dpkt.ip.IP_PROTO_ICMP):
        icmp = ip.data
        #print(repr(icmp))
        # do_not_fragmnet = bool(ip.off & dpkt.ip.IP_DF)
        '''more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        if (more_fragments == 1):
            fragment_count+=1
            continue

        if ((more_fragments == 0) and (fragment_count > 0)):
            offset_of_last_fragment = ip.off & dpkt.ip.IP_OFFMASK
            fragment_count=0'''
    '''if ip.p == dpkt.ip.IP_PROTO_ICMP:

        dest_ip = socket.inet_ntoa(ip.dst)

            # print(dest_ip)
        src_ip = socket.inet_ntoa(ip.src)
        if (dest_ip == src_ip_addr) and (src_ip != dst_ip_addr):

                # src_ip = socket.inet_ntoa(ip.src)
                # print(src_ip)
            if src_ip not in router:
                router.append(src_ip)
        ##print out the number of
    print(ip.p)
print(src_ip_addr)
print(dst_ip_addr)'''
#print(offset_of_last_fragment)
if len(previous_id)<1:
    print("The number of fragments created from the orginal datagram is:" + str(0))
    print("The offset of the last fragment is: " + str(0))
else:
    first_frag = previous_id[0]
    for i in range(len(previous_id)):
        if(previous_id[i]==first_frag):
            fragment_count+=1

    print("The number of fragments created from the orginal datagram is:" +str(fragment_count))
    print("The offset of the last fragment is: "+str(offset_of_last_fragment))