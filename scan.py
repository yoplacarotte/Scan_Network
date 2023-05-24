import socket
import argparse
import netifaces as ni
import ipaddress
from smb.SMBConnection import SMBConnection


def getNetwork():
    ### Grab the network ip
    ### INPUT = NOTHING
    ### OUTPUT = string
    
    iface = ni.gateways()
    info = ni.ifaddresses(iface['default'][ni.AF_INET][1])
    info = info[ni.AF_INET][0]
    addr = info['addr']
    netmask = info['netmask']
    cidr = ipaddress(netmask)
    print(addr)
    print(netmask)
    print(cidr)
    #return addr + '/' + str(cidr)




#ipNetwork = ipaddress.IPv4Network(getNetwork(), strict=False)
#print(ipNetwork)

getNetwork()