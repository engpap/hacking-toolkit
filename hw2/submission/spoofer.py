from scapy.all import IP, UDP, send, Raw

def send_packet(src_ip, dst_ip, dst_port, payload):
    """This function sends a UDP packet with the given payload from 'src_ip' to 'dst_ip:dst_port'.

    Arguments:
        src_ip (str):  Source IP address.
        dst_ip (str): Destination IP address.
        dst_port (int): Destination port.
        payload (bytes): Payload to send in bytes.
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