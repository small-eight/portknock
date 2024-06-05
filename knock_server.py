from scapy.all import *
import subprocess


def creat_callback(protocol,destination_port,filterlist):
    def packet_callback(packet):
        # 这里可以添加对捕获到的数据包的处理逻辑
        if src_ip_list[0]=="":
            print('抓到第一次包',packet['TCP'])
            src_ip_list[0]=(packet['IP'].src)
            sniff(iface="eth0", prn=my_packet_callback, store=False, count=1, filter=filterlist[1], timeout=5)
        elif src_ip_list[0]==packet['IP'].src and src_ip_list[1]=='':
            print('抓到第二次包', packet['TCP'])
            src_ip_list[1]=packet['IP'].src
            sniff(iface="eth0", prn=my_packet_callback, store=False, count=1, filter=filterlist[2], timeout=5)
        elif src_ip_list[1]==packet['IP'].src:
            print('抓到第三次包', packet['TCP'])
            add_iptables_rule(protocol,packet['IP'].src,destination_port)

    return packet_callback


def add_iptables_rule(protocol, source_ip, destination_port):
    # 检查协议是否为tcp或udp
    if protocol.lower() not in ['tcp', 'udp']:
        raise ValueError("Protocol must be tcp or udp")

        # 检查端口是否为整数且在1-65535范围内
    if not 1 <= int(destination_port) <= 65535:
        raise ValueError("Port must be an integer between 1 and 65535")

        # 构造iptables命令
    cmd = f"sudo iptables -A INPUT -p {protocol} -s {source_ip} --dport {destination_port} -j ACCEPT"

    # 执行命令
    try:
        subprocess.check_call(cmd, shell=True)
        print(
            f"Rule added successfully for protocol {protocol}, source IP {source_ip}, destination port {destination_port}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to add rule: {e}")

if __name__ == '__main__':
    port1=19578
    port2=9628
    port3=33546
    filter1 = f'tcp and dst port {port1}'
    filter2 = f'tcp and dst port {port2}'
    filter3 = f'tcp and dst port {port3}'
    filterlist=[filter1,filter2,filter3]
    src_ip_list=['']*3
    protocol="tcp"
    destination_port="22"
    my_packet_callback=creat_callback(protocol, destination_port,filterlist)
    print("超时时间为5S：")
    sniff(iface="eth0", prn=my_packet_callback, store=False,count=1,filter=filterlist[0])