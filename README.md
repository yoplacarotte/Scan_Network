### **Package version :**
```
pip 23.2
python 3.11.6
netifaces 0.11
```

### **Module Install :**
```
python3 -m venv myenv
source myenv/bin/activate

pip install netifaces
```

### **Help module :**
```python
usage: scan.py [-h] [-s] [-P P] [-CP] [-ping] [-ip IP] [-n N] [-banner] [-rapport]

options:
  -h, --help  show this help message and exit
  -s          Scan all the connected device on the same WiFi/Network as you.
  -P P        Option to precise the ports to scan (separated by a coma), or the range of ports (separated by a -)
  -CP         Option that scan common ports : [21,22,80...]
  -ping       Only ping hosts
  -ip IP      Scan ip given
  -n N        Scan network given : 10.10.10.1/24
  -banner     Check banner
  -rapport    Write output in a file
```

### **Execution exemple :**
```
Print help menu :
python3 scan.py -h

Ping every host in the same network :
python3 scan.py -s -ping

Scan port 1 to 1024 for each host in network 192.168.1.0/24 :
python3 scan.py -n 192.168.1.0/24

Scan a range of ports on host 192.168.1.1 :
python3 scan.py -ip 192.168.1.1 -P 80-88

Scan common port on host 192.168.1.1 and grab banner :
python3 scan.py -ip 192.168.1.1 -CP -banner

Scan port 80 and 443 on host 192.168.1.1, grab banner and write output in file:
python3 scan.py -ip 192.168.1.1 -P 80,443 -banner -rapport
```