import nmap
import socket

host = socket.gethostname()
my_ip = socket.gethostbyname(host)

scanner = nmap.PortScanner()
print('Welcome, this is a simple nmap scanner...')
print(f'Scanner version: {scanner.nmap_version()}')

ip_addr = input('Enter the IP address to scan: ')
if not ip_addr:
    ip_addr = my_ip
    print('IP address left blank.')
    print(f'Scanning your IP address ({ip_addr})... ')

scan_type = input('''Please enter the type of scan you want to run:
        1) SYN ACK Scan
        2) UDP Scan
        3) Comprehensive Scan
        >>> ''')

if scan_type == '1':
    print('You selected option 1: SYN ACK Scan')
    print('Scanning...')
    scanner.scan(ip_addr, '1-1024', '-v -sS')
    print(f'Scanner Info: {scanner.scaninfo()} ')
    print(f'IP Status: {scanner[ip_addr].state()} ')
    print(f'Protocol: {scanner[ip_addr].all_protocols()} ')
    print(f'Open ports: {scanner[ip_addr]["tcp"].keys()} ')
elif scan_type == '2':
    print('You selected option 2: UDP Scan')
    print('Scanning...')
    scanner.scan(ip_addr, '1-1024', '-v -sU')
    print(f'Scanner Info: {scanner.scaninfo()} ')
    print(f'IP Status: {scanner[ip_addr].state()} ')
    print(f'Protocol: {scanner[ip_addr].all_protocols()} ')
    print(f'Open ports: {scanner[ip_addr]["udp"].keys()} ')
elif scan_type == '3':
    print('You selected option 3: Comprehensive Scan')
    print('Scanning...')
    scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
    print(f'Scanner Info: {scanner.scaninfo()} ')
    print(f'IP Status: {scanner[ip_addr].state()} ')
    print(f'Protocol: {scanner[ip_addr].all_protocols()} ')
    print(f'Open ports: {scanner[ip_addr]["tcp"].keys()} ')
else: 
    print('Stop playing around!')