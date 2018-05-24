# -*- coding: utf-8 -*
'''
	A very simple raw socket implementation in Python
'''

import sys, socket
from struct import *

def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)

def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = (ord(msg[i]) << 8 ) + ord(msg[i+1])
        s = carry_around_add(s, w)
    return ~s & 0xffff

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except socket.error,msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

ip_source = '127.0.0.1' #本机IP
ip_dest = '127.0.0.1'	#也可以用域名：socket.gethostbyname('www.microsoft.com')

#填写ip header
ip_ver = 4			# ipv4
ip_ihl = 5			# Header Length =5, 表示无options部分
ip_dscp = 0			# 以前叫tos，现在叫dscp
ip_total_len = 0		# left for kernel to fill
ip_id = 22222			# fragment相关，随便写个
ip_frag_offset = 0		# fragment相关
ip_ttl = 255			# *nix下TTL一般是255
ip_protocol = socket.IPPROTO_UDP	# 表示后面接的是tcp数据
ip_checksum = 0			# left for kernel to fill
ip_saddr = socket.inet_pton(socket.AF_INET, ip_source)	# 两边的ip地址
ip_daddr = socket.inet_pton(socket.AF_INET, ip_dest)

ip_ver_ihl = (ip_ver << 4) + ip_ihl	# 俩4-bit数据合并成一个字节

# 按上面描述的结构，构建ip header。
ip_header = pack('!BBHHHBBH4s4s' , ip_ver_ihl, ip_dscp, ip_total_len, ip_id, ip_frag_offset, ip_ttl, ip_protocol, ip_checksum, ip_saddr, ip_daddr)


udp_sport = 8081	# Icmp包的类型及代码 类型8 代码0
udp_dport = 8081		# icmp包校验和
udp_checksum = 0	# Icmp包标识符
udp_length = 0		# ICMP包的序列号



# 按上面描述的结构，构建icmp_header。
udp_header = pack('!HHHH' , udp_sport, udp_dport, udp_checksum,udp_length)

# 写点东西作为data部分(可选)
payload_data = 'wordpress.youran.me'

# 构建pseudo ip header
psh_saddr = ip_saddr
psh_daddr = ip_daddr
psh_reserved = 0
psh_protocol = ip_protocol
psh_udp_len = len(udp_header) + len(payload_data)
psh = pack('!4s4sBBH', psh_saddr, psh_daddr, psh_reserved, psh_protocol, psh_udp_len)

# 创建最终用于checksum的内容
chk = psh + udp_header + payload_data

# 必要时追加1字节的padding
if len(chk) % 2 != 0:
	chk += '\0'

udp_checksum = checksum(chk)

# 重新构建tcp_header，把checksum结果填进去
udp_length=psh_udp_len
udp_header = pack('!HHHH' , udp_sport, udp_dport, udp_checksum,udp_length)
# 最终的tcp/ip packet！
packet = ip_header + udp_header + payload_data
# 发送出去
i = 0
while True:
    i = i+1
    s.sendto(packet, (ip_dest, 0))
    if i ==1000000:
        break
© 2018 GitHub, Inc.