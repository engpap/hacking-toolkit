import argparse
import socket
import threading
import paramiko
from collections import defaultdict
import os
import time

'''
To run the honeypot, run the following command:
python honeypot.py -p [port]

ex:
python honeypot.py -p 22
'''

'''
How to test TASK1:
ssh -p 22 carlo@127.0.0.1   
'''
DEBUG = True
NUM_ATTEMPTS = 1
SERVER_KEY_PATH = '/Users/dre/Desktop/NetSecurity/homeworks/cs468/hw5/server.key'
IDLE_TIMEOUT = 60  # seconds

# Dictionary to store login attempts
login_attempts = {}

def debugPrint(message):
    if DEBUG:
        print(message)

class SSHHoneypot(paramiko.ServerInterface):
    def __init__(self):
        self.login_attempts = {}
        self.username = None
        self.event = threading.Event()
        #self.username_list = self.load_username_list()

    def check_auth_none(self, username):
        
        if username not in self.login_attempts:
            self.login_attempts[username] = 0
        self.login_attempts[username] += 1

        debugPrint(f"Login attempt > #{self.login_attempts[username]} for {username}")

        if self.login_attempts[username] >= NUM_ATTEMPTS:
            debugPrint(f"Connection granted for {username} on attempt #{self.login_attempts[username]}")
            self.username = username
            return paramiko.AUTH_SUCCESSFUL
        
        return paramiko.AUTH_FAILED


    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True
    
    """def load_username_list(self):
        try:
            with open('hw5/hw5_files/usernames.txt', 'r') as file:
                usernames = file.read().splitlines()
            return usernames
        except FileNotFoundError:
            print(f"Error: The file usernames.txt was not found.")
            return []"""


def process_command(channel, command, username):
    if command == 'exit':
        channel.send('\r\nGoodbye!\n')
        return True
    channel.send(f'\r\nCommand {command} executed\n')
    return False

def handle_client(client):
    transport = paramiko.Transport(client)

    if os.path.exists(SERVER_KEY_PATH):
        key = paramiko.RSAKey.from_private_key_file(SERVER_KEY_PATH)
    else:
        key = paramiko.RSAKey.generate(2048)

    transport.add_server_key(key)

    server = SSHHoneypot()
    transport.start_server(server=server)

    channel = transport.accept(20)
    if channel is None:
        print("Client did not open a channel.")
        return

    server.event.wait(10)
    if not server.event.is_set():
        print("Client never asked for a shell.")
        return

    try:
        channel.send('Welcome to the honeypot\n')
        last_active = time.time()
        channel.send(f'\r\n{server.username}@honeypot:/$ ')  # Send initial prompt

        command_buffer = ''  # Buffer to accumulate command characters

        while True:
            if time.time() - last_active > IDLE_TIMEOUT:
                print("Connection idle for too long. Disconnecting.")
                break

            if channel.recv_ready():
                char = channel.recv(1).decode('utf-8')  # Read one character at a time
                if char == '\r' or char == '\n':  # Check for carriage return or newline
                    if command_buffer.strip():  # If there's a command in the buffer
                        process_command(channel, command_buffer, server.username)
                        last_active = time.time()  # Reset the activity timer
                        command_buffer = ''  # Clear the buffer for the next command
                    channel.send(f'\r\n{server.username}@honeypot:/$ ')  # Send prompt for next command
                else:
                    command_buffer += char  # Add character to buffer

            time.sleep(0.1)  # Prevents high CPU usage in the loop
    except Exception as e:
        print(f'Error: {e}')
    finally:
        channel.close()
        client.close()

def start_server(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', port))
    sock.listen(100)
    print(f'SSH Honeypot running on port {port}...')

    while True:
        client, addr = sock.accept()
        print(f'Connection from {addr[0]}:{addr[1]}')
        client_thread = threading.Thread(target=handle_client, args=(client,))
        client_thread.start()


def main():
    parser = argparse.ArgumentParser(description='Honeypot', add_help=False)
    parser.add_argument('-p', '--port', default=None, help='Port to listen on.')
    args = parser.parse_args()

    if DEBUG:
        args.port = "22"

    print("Arguments: {}".format(args))
    if args.port is None:
        print("No port specified. Exiting...")
        exit(1)

    start_server(int(args.port))

    

if __name__ == "__main__":
    main()