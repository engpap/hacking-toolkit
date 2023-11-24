import argparse
import socket
import threading
import paramiko
import os
import time

'''
To run the honeypot, run the following command:
python honeypot.py -p [port]

Example:
python honeypot.py -p 22

To connect to the honeypot, run the following command from another terminal:
ssh -p 22 carlo@127.0.0.1   

Make sure to set in the ssh_config file the following:
Host *
    NumberOfPasswordPrompts 10
'''

DEBUG = False
NUM_ATTEMPTS = 5
SERVER_KEY_PATH = '/Users/dre/Desktop/NetSecurity/homeworks/cs468/hw5/server.key'
IDLE_TIMEOUT = 60  # seconds

# Global variable for the simulated file system: Root directory with no files
file_system = {'/': {}}

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

    def check_auth_password(self, username, password):
        
        if username not in self.login_attempts:
            self.login_attempts[username] = 0
        self.login_attempts[username] += 1

        debugPrint(f"Login attempt > #{self.login_attempts[username]} for {username}")

        if self.login_attempts[username] >= NUM_ATTEMPTS:
            debugPrint(f"Connection granted for {username} on attempt #{self.login_attempts[username]}")
            self.username = username
            return paramiko.AUTH_SUCCESSFUL
        
        return paramiko.AUTH_FAILED

    # The following function needs to be overriden in order to avoid this error: `channel 0: open failed: administratively prohibited: `
    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    # The following function needs to be overriden in order to avoid this error: `shell request failed on channel 0`
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    # The following function needs to be overriden in order to avoid this error: `PTY allocation request failed on channel 0`
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True
    

def process_command(channel, command, username):
    global file_system
    split_input_command = command.split()
    debugPrint(f"\nReceived command parts: {split_input_command}")

    def is_valid_filename(filename):
        return filename.endswith('.txt')

    if split_input_command[0] == 'ls':
        current_files = ' '.join(file_system['/'].keys())
        channel.send(f'\r\n{current_files}')
        debugPrint("Executed ls command")

    elif split_input_command[0] == 'echo' and '>' in command:
        parts = command.split('>')
        if len(parts) != 2:
            channel.send(f'\r\nInvalid echo command format')
            debugPrint(f"Invalid echo command format: {command}")
            return False

        content_part, filename = parts
        filename = filename.strip()  # Remove leading & trailing whitespaces
        content = ' '.join(content_part.split()[1:]).strip('"')  # Remove echo and extra quotes

        if not is_valid_filename(filename):
            channel.send(f'\r\nUnknown file extension\n')
            debugPrint(f"Unknown file extension error for filename: {filename}")
            return False
        
        file_system['/'][filename] = content
        channel.send(f'\r\nFile {filename} created')
        debugPrint(f"File created: {filename} with content: {content}")

    elif split_input_command[0] == 'cat':
        filename = split_input_command[1]
        if not is_valid_filename(filename):
            channel.send(f'\r\nUnknown file extension')
            debugPrint(f"Unknown file extension error for filename: {filename}")
            return False
        if filename in file_system['/']:
            channel.send(f'\r\n{file_system["/"][filename]}')
            debugPrint(f"Displayed content of file: {filename}")
        else:
            channel.send(f'\r\nFile {filename} not found')
            debugPrint(f"File not found error for filename: {filename}")

    elif split_input_command[0] == 'cp':
        src, dest = split_input_command[1], split_input_command[2]
        if not all(is_valid_filename(f) for f in [src, dest]):
            channel.send(f'\r\nUnknown file extension')
            debugPrint(f"Unknown file extension error for filenames: {src}, {dest}")
            return False
        if src in file_system['/']:
            file_system['/'][dest] = file_system['/'][src]
            channel.send(f'\r\nFile {dest} created with content from {src}')
            debugPrint(f"Copied content from {src} to {dest}")
        else:
            channel.send(f'\r\nFile {src} not found\n')
            debugPrint(f"File not found error for source file: {src}")
    
    elif command.strip().lower() in ['exit', 'quit']:
        channel.send('\r\nGoodbye!\n')
        debugPrint(f"Closing connection for {username}")
        return True

    else:
        channel.send(f'\r\nCommand {command} not found')
        debugPrint(f"Command {command} not executed. It's not found.")
        return False
    
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

    channel = transport.accept(IDLE_TIMEOUT)
    if channel is None:
        print("Client did not open a channel.")
        return

    server.event.wait(IDLE_TIMEOUT)
    if not server.event.is_set():
        print("Client never asked for a shell.")
        return

    try:
        channel.send('Welcome to the honeypot\n')
        last_active = time.time()
        channel.send(f'\r\n{server.username}@honeypot:/$ ')  # Send initial prompt

        command_buffer = ''  # Buffer to accumulate command characters

        while True:
            try:
                if time.time() - last_active > IDLE_TIMEOUT:
                    print(f"Connection idle for too long ({int(time.time() - last_active)} seconds). Disconnecting.")
                    break

                if channel.recv_ready():
                    char = channel.recv(1).decode('utf-8')  # read one character at a time

                    if char == '\x7f' or char == '\x08':  # handle backspace/delete key
                        if command_buffer:
                            command_buffer = command_buffer[:-1]  # Remove last character from buffer
                            channel.send('\b \b')  # Move cursor back, overwrite with space, then move back again
                    elif char == '\r' or char == '\n':  # Carriage return or newline
                        if command_buffer.strip():  # If there's a command in the buffer
                            if process_command(channel, command_buffer, server.username):
                                break  # Break out of the loop if the command was exit or quit
                            last_active = time.time()  # Reset the activity timer
                            command_buffer = ''  # Clear the buffer for the next command
                        channel.send(f'\r\n{server.username}@honeypot:/$ ')  # Send prompt for next command
                    else:
                        command_buffer += char  # Add character to buffer
                        channel.send(char) 
            except socket.error as e:
                print(f'Socket exception: {e}')
                break  # break out of the loop in case of socket error

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