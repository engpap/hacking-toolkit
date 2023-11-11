
import argparse
import socket
import threading
import re
'''
NOTE
The following command should work. Using a different IP or a port smaller than 1024 may result in access denied errors.
python proxy.py -m passive -i 127.0.0.1 -p 8080

To kill the process running on a port, use the following command on terminal:
lsof -i :8080 # Get the PID of the process running on port 8080
kill -9 <PID> # Kill the process
'''

'''
Program should execute using the following command and take in the following inline arguments:
>> python proxy.py [-m [active/passive] listening ip listening port
• -m: The mode you want your proxy to operate, which will either be active or passive.
• listening ip: The IP address your proxy will listen on connections on.
• listening port: The port your proxy will listen for connections on.
'''
DEBUG = True

def main():
    parser = argparse.ArgumentParser(description='Proxy', add_help=False)
    parser.add_argument('-m', '--mode', default=None, help='Mode of operation [active/passive].')
    parser.add_argument('-i', '--listening_ip', default=None, help='IP address to listen on.')
    parser.add_argument('-p', '--listening_port', default=None, help='Port to listen on.')

    args = parser.parse_args()
    print("Arguments: {}".format(args))
    
    if args.listening_ip is None:
        print("No listening IP provided. Exiting...")
        exit(1)
    
    if args.listening_port is None:
        print("No listening port provided. Exiting...")
        exit(1)

    if args.mode == "active":
        proxy_active(args.listening_ip, args.listening_port)
    elif args.mode == "passive":
        proxy_passive(args.listening_ip, args.listening_port)
    else:
        print("Invalid mode provided. Exiting...")
        exit(1)

def proxy_active(listening_ip, listening_port):
    print("Active mode selected.")
    print("Listening on {}:{}".format(listening_ip, listening_port))


'''
In this mode your proxy, in addition to forwarding packets, should continuously look for the
presence of the following information in packets and log them to to a file named info 1.txt. Note that your code
will be tested against a variety of inputs so be comprehensive as possible.
• Usernames/emails and passwords sent as query parameters, or submitted through a form.
• Anything resembling a credit card number or a social security number.
• Common North American names, US addresses and US based phone numbers.
• Cookies present along with the HTTP request
Hint: Make use of regular expressions to capture nuances in different format types, ensure you look at both request
and response packets. Remember, information can be passed in the URL and headers too.
'''
# Reference: https://docs.python.org/3/library/socket.html#module-contents
# A pair (host, port) is used for the AF_INET address family, where host is a string representing either 
# a hostname in internet domain notation like 'daring.cwi.nl' or an IPv4 address like '100.50.200.5', and port is an integer.
def proxy_passive(listening_ip, listening_port):
    print("Passive mode selected.")
    print("Listening on {}:{}".format(listening_ip, listening_port))

    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.bind((listening_ip, int(listening_port)))
    proxy_socket.listen(5)
    
    # For each incoming connection, create a new thread and handle the request
    while True:
        client_socket, _ = proxy_socket.accept()
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

def handle_client(client_socket):
    with client_socket:
        request = client_socket.recv(4096)
        data = request.decode('utf-8')
        # Parse the HTTP request to get the destination host and port
        host, port = get_destination_host_port(data)
        print("Handling request to host: {}, port: {}".format(host, port))

        process_data(data)
        # Forwarding the request to the destination server (simplified)
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((host, port))
        server_socket.sendall(request)
        response = server_socket.recv(4096)
        client_socket.sendall(response)

def get_destination_host_port(request_data):
    """
    Parses the HTTP request to extract the destination host and port.
    """
    lines = request_data.splitlines()
    for line in lines:
        if line.startswith("Host:"):
            host_line = line.split(" ")
            if len(host_line) >= 2:
                host = host_line[1].strip()
                # Check if port is specified in the host line
                if ":" in host:
                    host, port = host.split(":")
                    return host, int(port)
                return host, 80  # Default port for HTTP
    return None, None  # Host not found in the request

def process_data(data):
    # Regular expressions for different data types
    info_patterns = {
        'name': r'\b[A-Z][a-z]*\s[A-Z][a-z]*\b',  # Basic pattern for names, can be improved
        'birthday': r'\b\d{4}-\d{2}-\d{2}\b',  # Format: YYYY-MM-DD
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'password': r'password=[^&\s]*',
        'address': r'\d+\s[A-z]+\s[A-z]+',  # Simple address pattern, might need refinement
        'credit_card': r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b',  # Format: 1234 5678 9101 1121
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'phone': r'\b\d{3}[\s\-]?\d{3}[\s\-]?\d{4}\b',  # Format: 123-456-7890
        'city_state_zip': r'\b[A-Z][a-z]+,\s[A-Z]{2},\s\d{5}\b'  # Format: City, ST, 12345
    }

    found_info = {}
    for key, regex in info_patterns.items():
        match = re.search(regex, data)
        if match:
            found_info[key] = match.group()

    if found_info:
        log_info(found_info)
    
    if DEBUG:
        print(data)

def log_info(info):
    with open("info1.txt", "a") as f:
        for key, value in info.items():
            f.write(f"{key}: {value}\n")
        f.write("\n")  # Adds a new line for separation between entries


if __name__ == "__main__":
    main()
