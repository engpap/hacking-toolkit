'''

Capture the traffic from a network interface in promiscuous mode and detect DNS poisoning
attack attempts, such as those generated by your dnsinject tool or by dnssnif.

Detection is based on identifying duplicate responses, which contain different answers for the same domain’s request (i.e., the observation
of the attacker’s spoofed response and the server’s actual response).

The order of arrival should not matter:
you should raise an alert irrespectively of whether the attacker’s spoofed response arrived before or after the
actual response.

You should make every effort to avoid false positives, e.g., consecutive legitimate responses
with different IP addresses for the same hostname due to DNS-based load balancing.

Your tool should conform to the following specification:

>> python dnsdetect.py [-i interface] [-r tracefile ]
-i: Listen on network device interface (e.g., eth0). If not specified, your program should select a default
interface to listen on.
-r: Read packets from tracefile (tcpdump format). If “-r” is not specified, your tool should detect
attempts of DNS spoofing for all the requests of the local machine’s IP address
'''
import sys
import argparse
from scapy.all import sniff, DNS, IP, DNSRR
from datetime import datetime
import netifaces
import ipaddress # To check if the IP address is private

TIME_DIFF_THRESHOLD = 10  # Time threshold in seconds

def extract_rdata(packet):
    if packet.haslayer(DNS) and packet[DNS].qr == 1:  # DNS Response
        rdata_values = []
        for i in range(packet[DNS].ancount):
            rr = packet[DNS].an[i]
            if rr.type == 1:  # Type 1 for A records
                rdata_values.append(rr.rdata)
        return rdata_values

def packet_callback(packet):
    '''
    To mark a packet as attack:
    - Same TXID of previous packet
    - Different IP address in the rdata field (None when the address does not exist, for example when the domain does not exist)
    - Same domain name (done it by accessing the dictionary through the domain name as key)
    - The packet is a DNS response (qr == 1)
    We don't check:
    - The source IP address (the attacker can spoof it)
    - Identification Value in the IP header (the attacker can spoof it)
    - The number of answers in the DNS response (the attacker can spoof it)
    How to avoid with false positive (Strategy):
    If two DNS responses with the same TXID but different IP addresses arrive within TIME_DIFF_THRESHOLD of each other, they're considered part of DNS-based load balancing and not marked as an attack.
    '''
    if packet.haslayer(DNS) and packet[DNS].qr == 1:  # DNS Response
        time_received = datetime.now()
        txid = packet[DNS].id
        queried_host = packet[DNS].qd.qname.decode('utf-8')
        ip_answer = extract_rdata(packet)
        print(f">>> Analyzing Packet for {queried_host}")

        # If there's no answer in the DNS rdata field, just put 'None' so we can compare it later
        if not ip_answer:
            ip_answer = ['None']

        # If the queried host is not in the dictionary, add it, so later we can use it
        if queried_host not in dns_responses:
            dns_responses[queried_host] = [(txid, ip_answer,  time_received, is_malicious(ip_answer))] 
        # If the queried host is in the dictionary, check if the TXID is the same
        else:
            legit_answers = []
            malicious_answers = []
            for prev_txid, prev_answers, prev_timestamp, is_mal in dns_responses[queried_host]:
                if txid == prev_txid:
                    time_diff = time_received - prev_timestamp
                    # if the time difference is within the threshold
                    if time_diff.total_seconds() < TIME_DIFF_THRESHOLD:
                    # Same TXID, check if the responses are different
                        if set(ip_answer) != set(prev_answers):
                            # Answers are different, log the attack
                            if is_mal:
                                malicious_answers.append(prev_answers)
                            else:
                                legit_answers.append(prev_answers)
                            if is_malicious(ip_answer):
                                malicious_answers.append(ip_answer)
                            else:
                                legit_answers.append(ip_answer)
                            log_attack(queried_host, txid, legit_answers, malicious_answers)

            dns_responses[queried_host].append((txid, ip_answer, time_received, is_malicious(ip_answer)))

def is_malicious(ip_answer):
    if 'None' in ip_answer:
        return False
    if any([is_private_ip(ip) for ip in ip_answer]):
        return True
    else:
        return False

def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        #print(f'IP  {ip} is private: {ip_obj.is_private}')
        return ip_obj.is_private
    except ValueError as e:
        print(f"Invalid IP address: {e}")
        return False


def print_dns_respones(dns_responses):
    print("DNS Responses:")
    for host, txid_ip in dns_responses.items():
        print(f"{host}:")
        for txid, ip in txid_ip:
            print(f"  TXID 0x{txid:04x} Response {ip}")
    print("")

def log_attack(domain, txid, legit_answers, malicious_answers):
    print(f"Attack Detected: {domain} TXID 0x{txid:04x}")
    with open('attack_log.txt', 'a') as f:
        f.write(f"- {datetime.now():%B %d %Y %H:%M:%S}\n")
        f.write(f"- TXID 0x{txid:04x} Request {domain[:-1]}\n")
        legit_answers_str = ', '.join([', '.join(map(str, ans)) for ans in legit_answers])
        malicious_answers_str = ', '.join([', '.join(map(str, ans)) for ans in malicious_answers])
        f.write(f"- Answer1: {legit_answers_str}\n")
        f.write(f"- Answer2: {malicious_answers_str}\n")
        f.write("\n")
    print(f"Attack Detected: {domain} TXID 0x{txid:04x}")

def get_default_interface():
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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='DNS Poisoning Detector')
    parser.add_argument('-i', '--interface', help='Network device interface (e.g., eth0)')
    parser.add_argument('-r', '--tracefile', help='Read packets from tracefile (tcpdump format)')
    args = parser.parse_args()

    dns_responses = {}

    if args.interface is None: 
        args.interface = get_default_interface()

    if args.tracefile:
        sniff(offline=args.tracefile, prn=packet_callback)
    else:
        sniff(iface=args.interface, prn=packet_callback, filter="udp port 53")
