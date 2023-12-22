from scapy.all import IP, UDP, send, Raw

def send_packet(src_ip, dst_ip, dst_port, payload):
    """Send a UDP packet with the given payload from src_ip to dst_ip:dst_port.

    Args:
        src_ip (str): The source IP address.
        dst_ip (str): The destination IP address.
        dst_port (int): The destination port.
        payload (bytes): The payload to send.
    """
    # Check payload size
    if len(payload) > 150:
        print("Cannot send packet: payload size exceeds 150 bytes!")
        return

    # Build the UDP packet by stacking layers
    packet = IP(src=src_ip, dst=dst_ip) / UDP(dport=dst_port) / Raw(load=payload)

    # Send the packet
    send(packet)
    #packet.show()

##################################################
#################### TESTING ####################
##################################################
import requests

def get_public_ip():
    try:
        response = requests.get('https://httpbin.org/ip')
        data = response.json()
        ip_address = data['origin']
        return ip_address
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

# Call the function to get your public IP address
public_ip = get_public_ip()

if public_ip:
    print(f"Your public IP address is: {public_ip}")
else:
    print("Failed to retrieve public IP address.")

src_ip = public_ip
dst_ip = "73.110.73.137"
dst_port = 56666 
payload = b"Welcome to CS-468!"
send_packet(src_ip, dst_ip, dst_port, payload)