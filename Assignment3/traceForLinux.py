import dpkt
import socket
import re
import statistics
import sys
class Pcap_file:
    router=[]
    previous_id=[]
    frag_count=1
    protocol=[]
    def __init__(self,filename):
        self.filename = filename
    def read_pcap_file(self):
        self.pcap = dpkt.pcap.Reader(open(self.filename,'rb'))
        return self.pcap
    def process_pcap_file(self):
        for ts,pkt in self.read_pcap_file():
            eth = dpkt.ethernet.Ethernet(pkt)
            ip = eth.data
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue
            if ip.p not in self.protocol:
                self.protocol.append(ip.p)
            if (ip.p == dpkt.ip.IP_PROTO_UDP) and (ip.ttl==1):
                self.src_ip_addr = socket.inet_ntoa(ip.src)
                self.dst_ip_addr = socket.inet_ntoa(ip.dst)
                more_fragments = bool(ip.off & dpkt.ip.IP_MF)
                if(more_fragments==1):
                    self.previous_id.append(ip.id)
                else:
                    if ip.id in self.previous_id:
                        self.offset_of_last_fragment = ip.offset
            if ip.p == dpkt.ip.IP_PROTO_ICMP:
                icmp = ip.data
                if((icmp.type==11) or (icmp.type==3)):
                    dest_ip = socket.inet_ntoa(ip.dst)

                    #print(dest_ip)
                    src_ip = socket.inet_ntoa(ip.src)
                    if (dest_ip == self.src_ip_addr) and (src_ip!=self.dst_ip_addr):

                        #src_ip = socket.inet_ntoa(ip.src)
                        #print(src_ip)
                        if src_ip not in self.router:
                            self.router.append(src_ip)
            ##print out the number of

        print(self.src_ip_addr)
        print(self.dst_ip_addr)
    def get_routers(self):
        return self.router
    def get_src(self):
        return self.src_ip_addr
    def get_dst(self):
        return self.dst_ip_addr
    def get_frag_count(self):
        if len(self.previous_id)>1 :
            first_one = self.previous_id[0]
            for i in range(len(self.previous_id)):
                if(self.previous_id[i]==first_one):
                    self.frag_count+=1
        else:
            self.frag_count=0
        return self.frag_count


def extract_port(str):
    port_num=[]
    m = re.search("sport=([0-9]+), ",str)
    found = m.group(1)
    port_num.append(found)
    m = re.search("dport=([0-9]+), ",str)
    found = m.group(1)
    port_num.append(found)
    return port_num
if(len(sys.argv)>2):
    filename = sys.argv[1]
else:
    filename = input("Please enter a filename")
pcap = Pcap_file(filename)
#pcap_file = pcap.read_pcap_file()

pcap_file = pcap.process_pcap_file()
array = pcap.get_routers()
#print("77: "+str(pcap.get_frag_count()))
pcap2 = Pcap_file(filename)
pcap_file2 = pcap.read_pcap_file()
src_ip_addr = []
dst_ip_addr = []
src_port_arr = []
dst_port_arr = []
ttl_arr = []
ts_arr = []

src_ip_addr2 = []
dst_ip_addr2 = []
src_port_arr2 = []
dst_port_arr2 = []
ts_arr2 = []
for ts,pkt in pcap_file2:
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data
    #udp = ip.data
    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        continue
    src_ip = socket.inet_ntoa(ip.src)
    dst_ip = socket.inet_ntoa(ip.dst)
    if (ip.p == dpkt.ip.IP_PROTO_UDP):
        udp = ip.data
        src_port = udp.sport
        dst_port = udp.dport
        ttl_num = ip.ttl
        src_ip_addr.append(src_ip)
        dst_ip_addr.append(dst_ip)
        src_port_arr.append(src_port)
        dst_port_arr.append(dst_port)
        ttl_arr.append(ttl_num)
        ts_arr.append(ts)
    if (ip.p == dpkt.ip.IP_PROTO_ICMP):
        icmp = ip.data
        if((icmp.type==11) or (icmp.type==3)):
            data = repr(icmp.data)
            port_num = extract_port(data)
            #print(port_num[0]+", "+port_num[1])
            ttl_num = ip.ttl
            src_ip_addr2.append(src_ip)
            dst_ip_addr2.append(dst_ip)
            src_port_arr2.append(int(port_num[0]))
            dst_port_arr2.append(int(port_num[1]))
            ts_arr2.append(ts)
#print(len(array))


#print(len(src_ip_addr2))
result_src_ip_arr=[]
result_dst_ip_arr=[]
result_src_port_arr=[]
result_dst_port_arr=[]
result_ts_arr=[]
result_ttl_arr=[]
'''find packet sent by source node according to matched port number'''
def find_match():
    for i in range(len(src_port_arr)):
        src_port = src_port_arr[i]
        dst_port = dst_port_arr[i]
        for j in range(len(src_port_arr2)):
            if((src_port==src_port_arr2[j])and(dst_port==dst_port_arr2[j])):
                result_src_port_arr.append(src_port)
                result_dst_port_arr.append(dst_port)
                result_src_ip_arr.append(src_ip_addr[i])
                result_dst_ip_arr.append(dst_ip_addr[i])
                result_ts_arr.append(ts_arr[i])
                result_ttl_arr.append(ttl_arr[i])

find_match()
#print(result_src_port_arr)
#print(src_port_arr2)
new_ip_addr=[]
new_rrt=[]

for i in range(len(result_src_port_arr)):
    for j in range(len(src_port_arr2)):
        if(result_src_port_arr[i]==src_port_arr2[j]):
            rrt_of_this_icmp = ts_arr2[j] - result_ts_arr[i]
            new_ip_addr.append(src_ip_addr2[i])
            new_rrt.append(rrt_of_this_icmp)
print(new_ip_addr)
print(new_rrt)
'''dictionary used to store intermediate node and relative rrt from source node to them'''
ip_dir={}
for i in range(len(new_ip_addr)):
    if new_ip_addr[i] not in ip_dir.keys():
        ip_dir[new_ip_addr[i]]=[]
        #ip_dir[new_ip_addr[i]].append(new_rrt[i])
    if new_ip_addr[i] in ip_dir.keys():
        ip_dir[new_ip_addr[i]].append(new_rrt[i])
#print("146: ")
#print(ip_dir)

print("The IP address of the source node: "+str(pcap.get_src()))
print("The IP address of ultimate destination node: "+str(pcap.get_dst()))
print("The IP addresses of the intermediate destination nodes:")
for i in range(len(array)):
    if array[i]!=dst_ip_addr:
        print("\trouter "+str(i+1)+": "+str(array[i]))
print("The values in the protocol field of IP headers:")
for i in range(len(pcap.protocol)):
    if(pcap.protocol[i]==1):
        print(str(1)+": "+"ICMP")
    if(pcap.protocol[i]==17):
        print(str(17) + ": " + "UDP")
    if(pcap.protocol[i]==6):
        print(str(6) + ": " + "TCP")


'''calculate rrt for each intermediate node, and print'''
for key,value in ip_dir.items():
    if(len(value)>1):
        print("The avg RRT between "+pcap.get_src()+" and "+ key+" is: "+str(statistics.mean(value))+", the s.d is: "+str(statistics.stdev(value)))
    else:
        #print(key+"average RRT is:"+str(statistics.mean(value))+" s.d is: "+str(0))
        print("The avg RRT between "+pcap.get_src()+" and "+ key+" is: "+str(statistics.mean(value))+", the s.d is: "+str(0))
