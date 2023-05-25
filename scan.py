import argparse, socket, os, subprocess, ping3, ipaddress, netifaces
from smb.SMBConnection import SMBConnection


def getNetwork():
    ### Grab the network ip
    ### INPUT = NOTHING
    ### OUTPUT = string
    
    iface = netifaces.gateways()
    info = netifaces.ifaddresses(iface['default'][netifaces.AF_INET][1])
    info = info[netifaces.AF_INET][0]
    addr = info['addr']
    netmask = info['netmask']
    netmask_wildcard = str(ipaddress.IPv4Address(int(ipaddress.IPv4Address(netmask))^(2**32-1)))
    CIDR = ipaddress.IPv4Address._prefix_from_ip_int(int(ipaddress.IPv4Address(netmask_wildcard))^(2**32-1))
    return str(addr) +"/"+ str(CIDR)

print(getNetwork())