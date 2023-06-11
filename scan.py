#!/usr/bin/python3
import argparse, socket, subprocess, ipaddress, netifaces
from smb.SMBConnection import SMBConnection

class color:
    OKGREEN = '\033[92m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

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
    print(f"Network : {ipNetwork}")
    for ip in ipNetwork:
        ipsplit = str(ip)
        tmpsplit = ipsplit.split(".")
        if tmpsplit[3] != "0" and tmpsplit[3] != "255":
            ScanPort(ip)
            if args.ping:
                print(Ping(ip))

def ScanPort(ip):
    # Check if the port is up !
    # INPUT = str, str
    # OUTPUT =

    print(f"IP : {ip}")
    if args.P:
        ListPort = args.P
        for port in ListPort.split(','):
            ConnectPort(str(ip),int(port))
    elif args.CP:
        ListPort = [21,22,53,80,443,445,8080]
        for port in ListPort:
            ConnectPort(str(ip),int(port))
    else:
        for port in range(1,1024):
            ConnectPort(str(ip),int(port))
    print()

def ConnectPort(ip,port):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    result = sock.connect_ex((ip,port))
        
    if result == 0:
        print(f"{color.OKGREEN}Port {port} Open{color.ENDC}")
        if args.banner:
            print(GetBanner(sock, port))
            #print()
    else:
        print(f"{color.FAIL}Port {port} Close{color.ENDC}")
        sock.close()

def Ping(ip):
    # Check if the host is up !
    # INPUT = ip : 192.168.1.1
    # OUTPUT = string : Host Unreachable or Host 192.168.1.1 Up !

    OutputPing = subprocess.run(f"ping -c 2 {ip}", shell=True, capture_output=True, text=True)

    if OutputPing.returncode == 1:
        PingMessage = f"Host {ip} Unreachable"
    if OutputPing.returncode == 0:
        PingMessage = f"Host {ip} Up !"
    return PingMessage

def DecodeBanner(data:bytes, codec = "ascii", test_exclude=[]):
    ### Decode bytes by trying differents codecs
    ### INPUT = bytes, string, list
    ### OUTPUT = string
    
    codecs = ["ascii", "utf-8", "utf-16", "utf-32", "unicode"]
    try:
        return data.decode(codec)
    except:
        for cod in codecs:
            if not cod in test_exclude:
                return DecodeBanner(data, cod, [*test_exclude, codec])
                break
    return str(data)

def GetBanner(sock, port):
    if port == 80 or port == 8080 or port == 443:
        banner = DecodeBanner(sock.recv(2048))
    elif port == 21:
        banner = DecodeBanner(sock.recv(2048))
    elif port == 22:
        banner = DecodeBanner(sock.recv(2048))
    elif port == 445:
        banner = DecodeBanner(sock.recv(2048))
    else:
        banner == DecodeBanner(sock.recv(2048))
    return banner

parser = argparse.ArgumentParser()
parser.add_argument("-s", action="store_true", help=f"scan all the connected device on the same WiFi as you.")
parser.add_argument("-P", help=f"option to precise the ports to scan (separated by a coma)")
parser.add_argument("-CP", action='store_true', help=f"option that scan common ports : [21,22,80...]")
parser.add_argument("-ping", action='store_true', help=f"ping function")
parser.add_argument("-ip", help=f"scan ip given")
parser.add_argument("-banner", action='store_true', help=f"Check banner")
args = parser.parse_args()

##MAIN##

if args.s:
    ScanNetwork()
elif args.ip:
    ScanPort(args.ip)
else:
    parser.print_help()
exit(1)