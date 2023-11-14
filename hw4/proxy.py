
import argparse
import socket
import threading
import re
from names_dataset import NameDataset
from urllib.parse import unquote
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



# Initialize the names dataset
names_data = NameDataset()

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
        request_data = request.decode('utf-8')
        # Parse the HTTP request to get the destination host and port
        host, port = get_destination_host_port(request_data)
        # Check if the destination port is for HTTPS (port 443), skip processing
        if port == 443:
            print("Skipping HTTPS request to host: {}, port: {}".format(host, port))
            return

        print("Handling HTTP request to host: {}, port: {}".format(host, port))

        # Process request data
        parse_http_packet(request_data, 'request')
        # Forwarding the request to the destination server (simplified)
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((host, port))
        server_socket.sendall(request)

        # Process server response
        response = server_socket.recv(4096)
        response_data = response.decode('utf-8')
        print("Handling response from host: {}, port: {}".format(host, port))
        parse_http_packet(response_data, 'response')
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

# Example: http://cs468.cs.uic.edu/submit?firstname=andrea&lastname=papa&birthday=2222-12-22&email=trial%40gmail.com&password=123465676&address=2343+West+Taylor+Street&credit-card=1234567812345678&social-security=111-11-1111&phone=123-404-9898&city=Chicago&state=IL&zip=55555
def parse_http_packet(data, type_packet):
    # Regular expressions for sensitive information
    regex_patterns = {
        'firstname_query': r'firstname=([^&\s]+)',
        'lastname_query': r'lastname=([^&\s]+)',
        'birthday_query': r'birthday=([^&\s]+)',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'password_query': r'password=([^&\s]+)',
        'credit_card': r'\b(?:\d[ -]*?){13,16}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'phone_number': r'\b\d{3}-\d{3}-\d{4}\b',
        'address_query': r'address=([^&]+)',
        'address': r'\d{1,6}(\s|\+)[A-Za-z0-9#\s\+,.]+(?:Street|St\.?|Avenue|Ave\.?|Road|Rd\.?|Boulevard|Blvd\.?|Drive|Dr\.?|Court|Ct\.?|Lane|Ln|Way|Plaza|Plz)\b',
        'city_query': r'city=([^&\s]+)',
        'state_query': r'state=([^&\s]+)',
        'zip_query': r'zip=([^&\s]+)'
    }

    output = {}
    # Check and log each pattern
    for key, pattern in regex_patterns.items():
        matches = re.findall(pattern, data)
        if matches:
            if key == 'address_query':
                matches = [match.replace('+', ' ') for match in matches]
            output[key] = matches
    
    # Extract names using names-dataset
    name_matches = extract_names(data)
    if name_matches:
        output['names'] = name_matches
        
    cookies = re.findall(r'Cookie: (.*?)(?:\r\n|$)', data)
    if cookies:
        output['cookies'] = cookies

    if 'Set-Cookie:' in data:
        cookies = re.findall(r'Set-Cookie: (.*?);', data)
        output['cookies'] = cookies

    log_info(output, type_packet)

def extract_names(data):
    """
    Extracts names using the names-dataset library.
    """
   # Decode URL-encoded strings
   # The unquote function reverses this encoding. It takes a URL-encoded string as input and returns a string with all the %xx escapes replaced by the characters they represent. For example:
    # example: unquote("Hello%20World") would return "Hello World".
    # example: unquote("Caf%C3%A9") would return "Café".
    decoded_data = unquote(data.lower())  # Convert data to lowercase

    # Choose an appropriate splitting method based on your data format
    # For example, splitting by '&' for URL query parameters
    words = re.split('&|\s|\n|=', decoded_data)

    # Get the top 100 common names in the US
    common_names = names_data.get_top_names(n=100, country_alpha2='US')
    male_names = common_names['US']['M']
    female_names = common_names['US']['F']
    all_genders_names = male_names + female_names
    common_names = [name.lower() for name in all_genders_names] # Convert common names to lowercase
    names = []
    for word in words:
        if word in common_names:
            names.append(word)
    return names


def log_info(info, data_type):
    with open("info1.txt", "a") as f:
        f.write(f"--- {data_type.upper()} DATA ---\n")
        for key, values in info.items():
            for value in values:
                f.write(f"{key}: {value}\n")
        f.write("\n")


if __name__ == "__main__":
    main()
