from geoip import geolite2
from scapy.all import *
import socket


############################################################
def get_serv(src_port, dst_port):
    try:
        service = socket.getservbyport(src_port)
    except:
        service = socket.getservbyport(dst_port)
    return service


############################################################
def locate(ip):
    loc = geolite2.lookup(ip)
    if loc is not None:
        return loc.country, loc.timezone
    else:
        return None

#############################################################

def analyzer(pkt):
    try:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        #########
        loc_src = locate(src_ip)
        loc_dst = locate(dst_ip)
        if loc_src is not None:
            countrt = loc_src[0]
            timezone = loc_dst[1]
        elif loc_dst is not None:
            countrt = loc_src[0]
            timezone = loc_dst[1]
        else:
            countrt = "UNKNOW"
            timezone = "UNKNOW"
        #########
        mac_src = pkt.src
        mac_dst = pkt.dst
        src_port = pkt.sport
        dst_port = pkt.dport

        if pkt.haslayer(ICMP):
            print("ICMP paker")
            # src_port = pkt.sport
            # dst_port = pkt.dport
            print("ip_src " + ip_src)
            print("ip_dst " + ip_dst)
            print("------------------")
            print("pkt.src " + mac_src)
            print("pkt.dst " + mac_dst)
            print("------------------")
            print("pkt.sport " + str(src_port))
            print("pkt.dport " + str(dst_port))
            print("------------------")
            print("timezone : " + timezone + "countrt : " + countrt)
            print("------------------")
            if pkt.haslayer(Raw):
                print(pkt[Raw].load)
            print("size packet is : " + str(len(pkt[ICMP])) + " pkt")
            print("#################################################################")
        else:
            src_port = pkt.sport
            dst_port = pkt.dport
            service = get_serv(src_port, dst_port)
            if pkt.haslayer(TCP):
                print("tcp paket")
                print("ip_src " + ip_src)
                print("ip_dst " + ip_dst)
                print("------------------")
                print("pkt.src " + mac_src)
                print("pkt.dst " + mac_dst)
                print("------------------")
                print("pkt.sport " + str(src_port))
                print("pkt.dport " + str(dst_port))
                print("------------------")
                print("timezone : " + timezone + "countrt : " + countrt)
                print("servies" + service)
                print("------------------")
                if pkt.haslayer(Raw):
                    print(pkt[Raw].load)
                print("size packet is : " + str(len(pkt[TCP])) + " pkt")
                print("###########################################################")

            if pkt.haslayer(UDP):
                print("udp paker")
                print("ip_src " + ip_src)
                print("ip_dst " + ip_dst)
                print("------------------")
                print("pkt.src " + mac_src)
                print("pkt.dst " + mac_dst)
                print("------------------")
                print("pkt.sport " + str(src_port))
                print("pkt.dport " + str(dst_port))
                print("------------------")
                print("timezone : " + timezone + "countrt : " + countrt)
                print("servies" + service)
                print("------------------")
                if pkt.haslayer(Raw):
                    print(pkt[Raw].load)
                print("size packet is : " + str(len(pkt[UDP])) + " pkt")
                print(
                    "#####################################################################")

    except:
        pass

print("***************start***************")
sniff(iface="wlp1s0", prn=analyzer)
