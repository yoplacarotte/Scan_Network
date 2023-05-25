#!/usr/bin/python3
import argparse, socket, os, subprocess, ipaddress, netifaces
from smb.SMBConnection import SMBConnection


def GetNetwork():
    # Get the network address
    # INPUT = NOTHING
    # OUTPUT = string : 192.168.1.0/24
    
    iface = netifaces.gateways()
    info = netifaces.ifaddresses(iface['default'][netifaces.AF_INET][1])
    info = info[netifaces.AF_INET][0]
    addr = info['addr']
    netmask = info['netmask']
    netmask_wildcard = str(ipaddress.IPv4Address(int(ipaddress.IPv4Address(netmask))^(2**32-1)))
    CIDR = ipaddress.IPv4Address._prefix_from_ip_int(int(ipaddress.IPv4Address(netmask_wildcard))^(2**32-1))
    return ipaddress.IPv4Network(addr +"/"+ str(CIDR), strict=False)

def ScanNetwork():
    # Check if the host is up !
    # INPUT = ip : 192.168.1.1
    # OUTPUT = string : Host Unreachable or Host 192.168.1.1 Up !
    
    ipNetwork = GetNetwork()
    for ip in ipNetwork:
        ipsplit = str(ip)
        tmpsplit = ipsplit.split(".")
        if tmpsplit[3] != "0" and tmpsplit[3] != "255":
            print(ip)

##MAIN##
ScanNetwork()
