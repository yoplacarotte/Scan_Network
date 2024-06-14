#!/usr/bin/python3.11
import argparse, socket, subprocess, os
import netifaces, ipaddress

class color:
    OKGREEN = '\033[92m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def GetNetwork():
    """
    Get network interfaces, determine CIDR and return and return it

    Paramaters
    ----------
    No parameters required

    Returns
    -------
    CIDR format

    Examples
    --------
    >>>GetNetwork()
    192.168.1.0/24
    """
    
    iface = netifaces.gateways() #Find network interfaces
    info = netifaces.ifaddresses(iface['default'][netifaces.AF_INET][1]) #Get network interface informations
    info = info[netifaces.AF_INET][0] #Select IPv4 informations
    addr = info['addr'] #Select interface network IP
    netmask = info['netmask'] #Select interface netmask
    netmask_wildcard = str(ipaddress.IPv4Address(int(ipaddress.IPv4Address(netmask))^(2**32-1))) #Determine reverse netmask
    CIDR = ipaddress.IPv4Address._prefix_from_ip_int(int(ipaddress.IPv4Address(netmask_wildcard))^(2**32-1)) #Determine CIDR form reverse netmask

    return ipaddress.IPv4Network(addr +"/"+ str(CIDR), strict=False)

def Ping(ip: str) -> str:
    """
    Get network interfaces, determine CIDR and return and return it

    Paramaters
    ----------
    ip : str
        The IP address to ping

    Returns
    -------
    str
        return if host is Up or Unreachable

    Examples
    --------
    >>>Ping(192.168.1.0)
    Host 192.168.1.0 Unreachable
    
    >>>Ping(192.168.1.1)
    Host 192.168.1.1 Up !
    """

    try: 
        OutputPing = subprocess.run(f"ping -c 2 {ip}", shell=True, capture_output=True, text=True) #Call subprocess to run ping command
        if OutputPing.returncode == 1:
            PingMessage = f"Host {ip} Unreachable"

        elif OutputPing.returncode == 0:
            PingMessage = f"Host {ip} Up !"

        else:
            print(f"Ping error with host : {ip}")

        return PingMessage #Return variable
    
    except Exception as err: #If anny error occured, we print that error
        print(err)


def ScanPort(ip: str):
    """
    Define the list of ports according to the arguiments

    Paramaters
    ----------
    ip : str
        The IP address to scan
    """

    print(f"IP : {ip}")
    if args.P:
        ListPort = args.P
        if "," in str(ListPort): #Condition format
            for port in ListPort.split(','): #Split list from ","
                ConnectPort(str(ip),int(port))

        if "-" in str(ListPort): #Condition format
            for port in range(int(ListPort.split('-')[0]), int(ListPort.split('-')[1])+1): #range with first element in arg and last to set the loop
                ConnectPort(str(ip),int(port))
            pass

        else:
            print(f"Error in format : {ListPort}") #Print error message and rewrite args to view error

    elif args.CP:
        ListPort = [21,22,25,53,80,88,110,123,137,138,139,162,389,443,445,464,587,636,989,990,3306,5432,8006,8080] #Set list of common port to scan
        for port in ListPort:
            ConnectPort(str(ip),int(port))

    else:
        for port in range(1,1024): #If no argument, the list goes from 1 to 1024
            ConnectPort(str(ip),int(port))
    print()

def ConnectPort(ip,port):
    """
    Get network interfaces, determine CIDR and return and return it

    Paramaters
    ----------
    ip : str
        The IP address to scan
    port : int
        The port to scan

    Returns
    -------
    str
        return if port is open or close

    Examples
    --------
    >>>ConnectPort("192.168.1.1", 80)
    IP : 192.168.1.1
    Port 80 Open
    """

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #Define sock
    sock.settimeout(0.5) #Set sock timeout
    result = sock.connect_ex((ip,port)) #Connect to the port

    if result == 0:
        print(f"{color.OKGREEN}Port {port} Open{color.ENDC}")
        if args.rapport:
            RapportList.append(f"IP : {ip}, Port {port} Open"+"\n")
        if args.banner:
            GetBanner(sock,port,ip)
    else:
        print(f"{color.FAIL}Port {port} Close{color.ENDC}")
        sock.close() #Close the connection

def DecodeBanner(data:bytes, codec = "ascii", test_exclude=[]) -> str:
    """
    Decode data receive from sock connection

    Paramaters
    ----------
    data : bytes
        The IP address to scan
    codec : str
        The port to scan
    test_exclude : list
    
    Returns
    -------
    str
        return banner decoded

    Examples
    --------
    >>>DecodeBanner(b'HTTP/1.1 400 Bad Request\r\nDate: Thu, 13 Jun 2024 20:48:25 GMT\r\nContent-Type: text/html\r\nContent-Length: 248\r\nConnection: close\r\n\r\n<html>\r\n<head><title>400 The plain HTTP request was sent to HTTPS port</title></head>\r\n<body>\r\n<center><h1>400 Bad Request</h1></center>\r\n<center>The plain HTTP request was sent to HTTPS port</center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n')
    HTTP/1.1 400 Bad Request
    Date: Thu, 13 Jun 2024 20:48:25 GMT
    Content-Type: text/html
    Content-Length: 248
    Connection: close

    <html>
    <head><title>400 The plain HTTP request was sent to HTTPS port</title></head>
    <body>
    <center><h1>400 Bad Request</h1></center>
    <center>The plain HTTP request was sent to HTTPS port</center>
    <hr><center>nginx</center>
    </body>
    </html>
    """

    codecs = ["ascii", "utf-8", "utf-16", "utf-32", "unicode"] #List of different codec
    try:
        return data.decode(codec) #return decoded data
    except:
        for cod in codecs: #loop over the list of codecs
            if not cod in test_exclude:
                return DecodeBanner(data, cod, [*test_exclude, codec])
                break
    return str(data) #return data as str

def GetBanner(sock, port, ip):
    """
    Decode data receive from sock connection

    Paramaters
    ----------
    sock : socket.socket
        The IP address to scan
    port : int
        Port to check banner
    ip : str
        Ip to check banner
    
    Returns
    -------
    str
        return banner decoded

    Examples
    --------
    >>>GetBanner(<socket.socket fd=3, family=2, type=1, proto=0, laddr=('0.0.0.0', 0)>, 80, "192.168.1.48")
    """

    if port == 80 or port == 8080 or port == 443 or port == 8006: #Check web service port
        try:
            sock.send(str.encode("GET / HTTP/1.1\r\nHost:"+ str(ip) +":"+ str(port) +"\\robots.txt\r\n\r\n"))
            banner = DecodeBanner(sock.recv(2048))
            if args.rapport:
                RapportList.append(banner+"\n")
            print(banner)

        except ConnectionResetError:
            print("Connexion error, reset by peer")
            banner = DecodeBanner(sock.recv(2048))
            if args.rapport:
                RapportList.append(banner+"\n")
      
    elif port == 21:
        sock.settimeout(5)
        banner = DecodeBanner(sock.recv(2048))
        print(banner)
        if args.rapport:
            RapportList.append(banner+"\n")

    elif port == 139:
        banner = subprocess.run(f"nmblookup -A {ip}", shell=True, capture_output=True, text=True)
        if args.rapport:
            RapportList.append(banner.stdout+"\n")
        print(banner.stdout)

    else:
        try:
            banner = DecodeBanner(sock.recv(2048))
            if args.rapport:
                RapportList.append(banner+"\n")
            print(banner)
            
        except:
            print("Banner unknown")

def Rapport(NameRapport: str):
    """
    Write data in a file

    Paramaters
    ----------
    NameRapport : str
        Name of the rapport
    
    Returns
    -------
    str
        Write data from list "RapportList" in the file

    Examples
    --------
    >>>Rapport("192.168.1.0")
    IP : 192.168.1.24, Port 80 Open
    HTTP/1.1 301 Moved Permanently
    Location: https://192.168.1.24:10443
    """

    if RapportList != []: #Verify if the list isn't empty
        path = os.getcwd() #Get path of the script
        if not os.path.exists(path+"/Rapport/"): #Verify if directory isn't exist
            os.makedirs(path+"/Rapport/") #Make dir if isn't exist
        pathRapport = path+"/Rapport/"+"Rapport_"+NameRapport+".txt" #Set path of rapport
        try:           
            with open(pathRapport, "w+") as FileRapport: #Open file with write right
                for data in RapportList: #Loop on the list
                    FileRapport.write(data) #Write data in the file
                FileRapport.close()
        except OSError: #Exception
            print(f"Can't open {pathRapport}")

def main():

    #Define args
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", action="store_true", help=f"Scan all the connected device on the same WiFi/Network as you.")
    parser.add_argument("-P", help=f"Option to precise the ports to scan (separated by a coma), or the range of ports (separated by a -)")
    parser.add_argument("-CP", action='store_true', help=f"Option that scan common ports : [21,22,80...]")
    parser.add_argument("-ping", action='store_true', help=f"Only ping hosts")
    parser.add_argument("-ip", help=f"Scan ip given")
    parser.add_argument("-n", help=f"Scan network given : 10.10.10.1/24")
    parser.add_argument("-banner", action='store_true', help=f"Check banner")
    parser.add_argument("-rapport", action='store_true', help=f"Write output in a file")

    #Variable declaration
    global args #Define args as global variable
    args = parser.parse_args()

    global RapportList
    RapportList = []

    if args.ip:
        NameRapport = str(args.ip)
        if args.ping:
            print(Ping(args.ip))

        if not args.ping:
            ScanPort(args.ip)

            if args.rapport:
                Rapport(NameRapport)

    elif args.s or args.n:
        if args.s:
            Network = ipaddress.IPv4Network(GetNetwork())
        elif args.n:
            Network = ipaddress.IPv4Network(args.n)

        print(f"Network : {Network}")
        NameRapport = str(Network)[:-3]
        RapportList.append(f"Network : {Network}"+"\n")
        if args.ping:
            for ip in Network:
                print(Ping(ip))
        
        elif not args.ping:
            for ip in Network:

                if str(ip).split(".")[3] != "0" and str(ip).split(".")[3] != "255":
                    ScanPort(ip)

            if args.rapport:
                Rapport(NameRapport)

    else:
        parser.print_help()
    exit(1)

if __name__ == '__main__':
    main()