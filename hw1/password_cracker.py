import hashlib

# Function to hash a password using multiple algorithms
def hash_password(password):
    md5_hash = hashlib.md5(password.encode()).hexdigest()
    sha1_hash = hashlib.sha1(password.encode()).hexdigest()
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()
    return md5_hash, sha1_hash, sha256_hash

def get_hashed_passwords():
    # Define an empty dictionary to store the key-value pairs
    user_data = {}

    # File path where shadow file is stored
    file_path = './hw1_files/shadow'

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
    # Initialize an empty list to store the data
    data_list = []

    # File path where the dictionary of password is stored
    file_path = './hw1_files/dictionary.txt' 

    # Open and read the file line by line
    with open(file_path, 'r') as file:
        for line in file:
            # Remove leading and trailing whitespace and add the line to the list
            data_list.append(line.strip())

    return data_list



user_data = get_hashed_passwords()
common_passwords = get_common_passwords()
user_data_cracked = []

'''
IDEA
For each word in the dictionary of common password, we hash it different using hashing algorithms, md5, sha1, sha25.
Then, we there eists a user in user_data whose hashed pawword is equal. If so, we store in user_data_cracked the
password in clear.
'''

for common_password in common_passwords:
        md5_hash, sha1_hash, sha256_hash = hash_password(common_password)

        for user, hashed_password in user_data.items():
            if hashed_password in [md5_hash, sha1_hash, sha256_hash]:
                result = {
                    "user": user,
                    "hashed_password": hashed_password,
                    "password": common_password,
                    "hash_algorithm": "MD5" if hashed_password == md5_hash else
                                      "SHA-1" if hashed_password == sha1_hash else
                                      "SHA-256"
                }
                user_data_cracked.append(result)

print(user_data_cracked)