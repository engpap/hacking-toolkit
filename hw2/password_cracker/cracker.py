import hashlib
import time
import os

current_dir = os.path.dirname(os.path.abspath(__file__))

def get_hashed_passwords():
    user_data = {}

    # File path where shadow file is stored
    file_path = os.path.join(current_dir, 'shadow')

    # Open and read the file line by line
    with open(file_path, 'r') as file:
        for line in file:
            # Split each line into key and value using ':'
            parts = line.strip().split(':')
            
            # Ensure that the line contains at least two parts (key and value)
            if len(parts) >= 2:
                # Assign the key and value to variables
                key = parts[0]
                value = parts[1]
                
                # Store the key-value pair in the dictionary
                user_data[key] = value

    return user_data


def get_common_passwords():
    data_list = []

    # File path where the dictionary of password is stored
    file_path = os.path.join(current_dir, 'dictionary.txt')

    # Open and read the file line by line
    with open(file_path, 'r') as file:
        for line in file:
            # Remove leading and trailing whitespace and add the line to the list
            data_list.append(line.strip())
    return data_list


# Function to hash a password using multiple algorithms
def hash_password(password):
    md5_hash = hashlib.md5(password.encode()).hexdigest()
    sha1_hash = hashlib.sha1(password.encode()).hexdigest()
    sha224_hash = hashlib.sha224(password.encode()).hexdigest()
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()
    sha384_hash = hashlib.sha384(password.encode()).hexdigest()
    sha512_hash = hashlib.sha512(password.encode()).hexdigest()
    sha3_224_hash = hashlib.sha3_224(password.encode()).hexdigest()
    sha3_256_hash = hashlib.sha3_256(password.encode()).hexdigest()
    sha3_384_hash = hashlib.sha3_384(password.encode()).hexdigest()
    sha3_512_hash = hashlib.sha3_512(password.encode()).hexdigest()
    blake2s_hash = hashlib.blake2s(password.encode()).hexdigest()
    blake2b_hash = hashlib.blake2b(password.encode()).hexdigest()


    return [md5_hash, sha1_hash, sha256_hash, sha224_hash, sha384_hash, 
            sha512_hash, sha3_224_hash, sha3_256_hash, sha3_384_hash, 
            sha3_512_hash, blake2s_hash, blake2b_hash]


# Caesar cipher: Use ASCII table for transformations for the given indexes.
#  When transforming characters use the indexes 65-122 and for the numbers 48-57. 
# Remember to stay in the bounds.

def caesar_cipher(text, shift):
    result = ""
    
    for char in text:
        if 'A' <= char <= 'Z':
            result += chr(((ord(char)-ord('A')+shift) % 26) + ord('A'))
        elif 'a' <= char <= 'z':
            result += chr(((ord(char)-ord('a')+shift) % 26) + ord('a'))
        elif '0' <= char <= '9':
            result += chr(((ord(char)-ord('0')+shift) % 10) + ord('0'))
        else:
            result += char 
    return result


def leetspeak(word):
    # Dictionary to map characters to their leetspeak equivalents
    leet_dict = {
        'a': '4',
        'e': '3',
        'l': '1',
        't': '7',
        'o': '0',
        's': '5',
        'g': '9',
    }
    
    leetspeak_word = ""
    
    # Iterate through each character in the input word
    for char in word:
        # If the character is in the leet_dict, replace it with its leetspeak equivalent
        if char.lower() in leet_dict:
            leetspeak_word += leet_dict[char.lower()]
        else:
            # If not found in the dictionary, keep the original character
            leetspeak_word += char
    
    return leetspeak_word


def print_user_data_cracked(user_data_cracked):
    for elem in user_data_cracked:
        print(elem)
        print('\n')

def save_passwords_to_file(user_data_cracked):
    # Order by username
    user_data_cracked.sort(key=lambda x: x['user'])

    file_path = os.path.join(current_dir, 'passwords.txt')

    with open(file_path, 'w') as file:
        for entry in user_data_cracked:
            username = entry['user']
            password = entry['password']
            file.write(f'{username}:{password}\n')

if __name__ == "__main__":

    common_passwords = get_common_passwords()
    user_data_cracked = []

    hashed_password = 'b9703614d138ef18234e74df390c58b39a63b10ac56134d56e61d097'

    '''
    IDEA
    For each word in the dictionary of common password, we hash it different using hashing algorithms, md5, sha1, sha25.
    Then, we there eists a user in user_data whose hashed password is equal. If so, we store in user_data_cracked the
    password in clear.
    '''
    for common_password in common_passwords:
            
            hashes = hash_password(common_password)
            leek_hashes = hash_password(leetspeak(common_password))
            
            # Checks whether the hashed password exists in shadow
            if  (hashed_password in hashes):
                result = {
                    "user": 'iamauser',
                    "hashed_password": hashed_password,
                    "password": leetspeak(common_password) if (hashed_password in leek_hashes) else common_password,
                    "salt": False,
                    'caesar': False,
                    'leek': (hashed_password in leek_hashes),
                    'substitution_cipher' : False
                }
                user_data_cracked.append(result)

    print_user_data_cracked(user_data_cracked)
