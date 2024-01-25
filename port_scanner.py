#!/usr/bin/env python
"""
SYNOPSIS

    port_scanner.py [TARGET ADDRESS] [-help] [-verbose]
    This script requires command line arguments to run.

DESCRIPTION

This program checks if the port is open, closed or filtered by sending a TCP packet
to a target IP address. It checks 15 ports:
            21-FTP, 22-SSH, 23-Telnet, 25-SMTP,
            53-DNS, 80-HTTP, 101-POP3,
            135-Windows RPC, 137-Windows NetBIOS over TCP,
            138-Windows NetBIOS over TCP, 139-Windows NetBIOS over TCP, 443-HTTPS,
            1433-Microsoft SQL Server, 1434-Microsoft SQL Server, 8080-HTTP Alternative.

Command line usage: port_scanner.py [TARGET ADDRESS]

Options:
    -help           Shows this message and exit
    -verbose        Shows the process of sending and receiving for all packets

The target address can be an IP address OR domain name OR CIDR/slash notation

EXAMPLES

port_scanner.py 1.1.1.1               
  
142.250.70.164 in port 21 has no response: port is filtered.
142.250.70.164 in port 22 has no response: port is filtered.
142.250.70.164 in port 23 has no response: port is filtered.
142.250.70.164 in port 25 has no response: port is filtered.
142.250.70.164 in port 53 has no response: port is filtered.
142.250.70.164 in port 80 responded with SA: port is open.
142.250.70.164 in port 101 has no response: port is filtered.
142.250.70.164 in port 135 has no response: port is filtered.
142.250.70.164 in port 137 has no response: port is filtered.
142.250.70.164 in port 138 has no response: port is filtered.
142.250.70.164 in port 139 has no response: port is filtered.
142.250.70.164 in port 443 responded with SA: port is open.
142.250.70.164 in port 1433 has no response: port is filtered.
142.250.70.164 in port 1434 has no response: port is filtered.
142.250.70.164 in port 8080 has no response: port is filtered.

AUTHOR

    Dyn Candido <p276126@tafe.wa.edu.au>

LICENSE

    This script is the exclusive and proprietary property of
    TiO2 Minerals Consultants Pty Ltd. It is only for use and
    distribution within the stated organisation and its
    undertakings.

VERSION

    0.1
"""

import sys
sys.path.append(r'c:\users\dynca\appdata\local\programs\python\python38-32\lib\site-packages')
from scapy.all import *

# If the user runs the scripts from an IDE, the user adds '-help' or the user does not enter 
# a target address to run the script, it prints out a help message and exits the program.
if '-help' in sys.argv or len(sys.argv) == 1:
    print("""Welcome to the port scanner. 
This program checks if the port is open, closed or filtered by sending a TCP packet
to a target IP address. It checks 15 ports: 
            21-FTP, 22-SSH, 23-Telnet, 25-SMTP,
            53-DNS, 80-HTTP, 101-POP3, 
            135-Windows RPC, 137-Windows NetBIOS over TCP,
            138-Windows NetBIOS over TCP, 139-Windows NetBIOS over TCP, 443-HTTPS, 
            1433-Microsoft SQL Server, 1434-Microsoft SQL Server, 8080-HTTP Alternative.""")
    print("""\nCommand line usage: port_scanner.py [TARGET ADDRESS]
    
Options:
    -help           Shows this message and exit
    -verbose        Shows the process of sending and receiving for all packets""")
    sys.exit()

# If the user adds '-verbose' in the command line, it enables verbose. Otherwise, it is disabled.
if '-verbose' in sys.argv:
    verboseVal = 1
else:
    verboseVal = 0

#
destIP = sys.argv[1]
destPorts = [21,22,23,25,53,80,101,135,137,138,139,443,1433,1434,8080]
sourcePort = random.randint(1025,65534)

#
for eachPort in destPorts:
    packet = IP(dst=destIP) / TCP(sport=sourcePort,dport=eachPort)
    response = sr1(packet, timeout=1.5, verbose=verboseVal)

    if response == None:
        print(f'{packet.dst} in port {packet.dport} has no response: port is filtered.')
    elif response.getlayer(TCP).flags == 'SA':
        print(f'{packet.dst} in port {packet.dport} responded with {response.getlayer(TCP).flags}: port is open.')
    elif response.getlayer(TCP).flags == 'R' or 'RA':
        print(f'{packet.dst} in port {packet.dport} responded with {response.getlayer(TCP).flags}: port is closed.')
