import time
import matplotlib.pyplot as plt
import re
from collections import Counter

from password_cracker import get_common_passwords, get_hashed_passwords, hash_password, print_user_data_cracked, save_passwords_to_file

'''
Utility functions
'''
# Function to read text from a file and count letter occurrences
def count_letter_occurrences(text):
    letter_counts = {}
    for char in text:
        if char.isalpha():
            if char in letter_counts:
                letter_counts[char] += 1
            else:
                letter_counts[char] = 1
    return letter_counts

# Function to plot letter frequency
def plot_letter_frequency(letter_counts):
    letters = list(letter_counts.keys())
    counts = list(letter_counts.values())
    
    plt.bar(letters, counts)
    plt.xlabel('Letters')
    plt.ylabel('Frequency')
    plt.title('Letter Frequency in File')
    plt.show()


def get_decrypted_text(mapping):
    hinted_text = ''
    for char in encrypted_text:
        if char.isalpha() and char in mapping.keys():
            hinted_text += mapping[char]
        else:
            hinted_text += char
    return hinted_text

# Extract words from text using regular expressions
def extract_words(text):
    words = re.findall(r'\b\w+\b', text.lower())
    return words

# Return the letters that occurs twice consecutively inside a word of the input text
def find_double_consecutive_letters(words):
    result = []
    
    for word in words:
        for i in range(len(word) - 1):
            if word[i] == word[i + 1]:
                result.append(word)
                break  # We found a double consecutive letter, no need to check further in this word
    
    return result

def find_key_by_value(dictionary, target_value):
    for key, value in dictionary.items():
        if value == target_value:
            return key
    return '-'  # Return '-' if the value is not found

def encrypt_substitution_cipher(mapping, plaintext):
    ciphertext = ''
    for char in plaintext:
        if char.isalpha():
            ciphertext += find_key_by_value(mapping, char)
        else:
            ciphertext += char
    return ciphertext



if __name__ == "__main__":

    '''
    Print the occurences of the letters in the encrypted text (and plot them on a histogram) to do analytics.
    '''
    file_path = "/Users/dre/Desktop/NetSecurity/homeworks/cs468/hw1/hw1_files/encrypted.txt"
    with open(file_path, 'r') as file:
        encrypted_text = file.read().lower()  # Read the file and convert to lowercase for case insensitivity

    letter_counts = count_letter_occurrences(encrypted_text)
    #plot_letter_frequency(letter_counts)
    sorted_letter_counts = dict(sorted(letter_counts.items(), key=lambda item: item[1], reverse=True))
    print('Sorted letter occurences in encrypted.txt :\n',sorted_letter_counts)
    print('Len: ', len(sorted_letter_counts.keys()))

    '''
    Print the occurences of the letters in the a English dictionary and compare it with the occurences in the encrypted text
    to guess some mappings. Basically, we can guess the mappings of the most occuring letters.

    Source: https://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
    '''
    english_dict_letter_values = {}

    with open('/Users/dre/Desktop/NetSecurity/homeworks/cs468/hw1/frequency', 'r') as file:
        # Iterate over each line in the file
        for line in file:
            # Split the line into letter and value using '=' as the separator
            parts = line.strip().split('=')
            # Check if there are exactly two parts
            if len(parts) == 2:
                letter = parts[0].strip().lower()
                value = float(parts[1].strip())
                # Store the letter and its corresponding value in the dictionary
                english_dict_letter_values[letter] = value

    sorted_english_dict_letter_values = dict(sorted(english_dict_letter_values.items(), key=lambda item: item[1], reverse=True))
    print('Sorted letter occurences in English dictionary :\n',sorted_english_dict_letter_values)
    print('Len: ', len(sorted_english_dict_letter_values.keys()))

    '''
    Try to do a first mapping based on the most occuring letters in the two Python dictionaries.
    Sort the Python dictionaries to do an order mapping from the most to the least occuring letter.
    '''

    most_occurring_letters_mapping = {}

    # Get the sorted keys from letter_counts and English dictionary
    sorted_letter_keys = list(sorted_letter_counts.keys())
    sorted_english_dict_keys = list(sorted_english_dict_letter_values.keys())

    # Create the mapping based on the index order
    for i in range(len(sorted_letter_keys)):
        most_occurring_letters_mapping[sorted_letter_keys[i]] = sorted_english_dict_keys[i]

    print("Letter Mapping : \n", most_occurring_letters_mapping)

    # Keep the first 5 elements of the dictionary: it is not likely the the least occuring will help decrypting the text at this stage
    most_occurring_letters_mapping = dict(list(most_occurring_letters_mapping.items())[:5])
    print("Here's the hinted text :\n", get_decrypted_text(most_occurring_letters_mapping))


    '''
    Try to do a second mapping based on the most occuring words in the encrypted_text and the English language.
    Source: https://www3.nd.edu/~busiforc/handouts/cryptography/cryptography%20hints.html
    '''
    # Extract words from the text
    words = extract_words(encrypted_text)
    # Count the occurrences of each word
    word_counts = Counter(words)
    # Print the 10 most common words in the encrypted_text
    for word, count in word_counts.most_common(10):
        print(f'{word}: {count}')


    '''
    The following is a dictionary that contians the mapping of the substitution cipher.
    I started mapping based on the previous analysis: most occuring letters, most occuring words.
    Then, by reading the partially decrypted text, I guessed (using a trial-and-error approach) the remaining mappings.
    '''
    guessed_mapping =   { 
                        # 'h': 'e', # Most occuring letter: _____ now not necessary anymore because of 'the'
                        'm':'i',    # Most occuring one-letter word is either 'e' or 'i'
                        # 's':'a',  # Second most occuring one-letter word is either 'e' 't' 'a' or 'o', from the context we can guess it is 'a': ______ now not necessary anymore because of 'and'
                        'b': 't', 'c': 'h', 'h': 'e',   # Most occuring two-letter word is 'the'
                        's': 'a', 'j': 'n', 'r':'d',    # Second occuring two-letter word is 'and'
            
                        'd': 's',   # Guess based on text
                        'u': 'v',   # Guess based on text
                        'q': 'f',   # Guess based on text
                        'e':'o',    # Guess based on text
                        'y':'r',    # Guess based on text
                        'a': 'g',   # Guess based on text
                        'z': 'u',   # Guess based on text
                        'v':'l',    # Guess based on text
                        'x': 'b',   # Guess based on text
                        'o': 'w',   # Guess based on text
                        'g': 'p',   # Guess based on text
                        'l': 'y',   # Guess based on text
                        'w':'c',    # Guess based on text
                        'f': 'm',   # Guess based on text
                        'k': 'q',   # Guess based on text
                        'n': 'z',   # Guess based on text

                        # In the partially decrypted_text there is 'tnocting' -> should be 'knocking'; thus, 't' to 'k' represents a viable mapping
                        't': 'k',

                        # Missing letters: 'i' and 'p'
                        # '-' indicates missing information
                        'i': '-',
                        'p': '-'
                    
                        } 
    print('\n\nFINAL VERSION:')
    print('Guessed mapping lenght: ',len(guessed_mapping.keys()))
    print("Here's the decrypted text using guessed mapping:\n", get_decrypted_text(guessed_mapping))
    print("Here's the re-encrypted text using guessed mapping:\n", encrypt_substitution_cipher(guessed_mapping, get_decrypted_text(guessed_mapping)))

    assert encrypted_text == encrypt_substitution_cipher(guessed_mapping, get_decrypted_text(guessed_mapping)), ">>> WARNING: WRONG DECRYPTION!"

    # Open the file in write mode ('w')
    with open('/Users/dre/Desktop/NetSecurity/homeworks/cs468/hw1/plaintext.txt', 'w') as file:
        # Write decrypted text to the file
        file.write(get_decrypted_text(guessed_mapping))

    '''
    Now we can decrypt the user7 password.
    ''' 
    user_data = get_hashed_passwords()
    common_passwords = get_common_passwords()
    user_data_cracked = []


    start_time = time.time() 
    for common_password in common_passwords:
            
        hashes = hash_password(encrypt_substitution_cipher(guessed_mapping, common_password))

        if user_data['user7'] in hashes:
            result = {
                    "user": 'user7',
                    "hashed_password": user_data['user7'],
                    "password": common_password,
                    "salt": False,
                    'caesar': False,
                    'leek': False,
                    'substitution_cipher' : True
                }
            user_data_cracked.append(result)
            del user_data['user7']
            break

    end_time = time.time()  # Record the end time
    elapsed_time = end_time - start_time  # Calculate the elapsed time
    print(f"Cracking user7 password took {elapsed_time} seconds")
    print_user_data_cracked(user_data_cracked)
    print('################################################################################')

    # Append a line of text to the end of the file
    # We do not use the `save_passwords_to_file` function in `password_cracker` file because it would overwrite the file.
    with open('/Users/dre/Desktop/NetSecurity/homeworks/cs468/hw1/passwords.txt', 'a') as file:
        for entry in user_data_cracked: 
            username = entry['user']
            password = entry['password']
            file.write(f'{username}:{password}\n')
        print('Saved user7 and their password in passwords.txt')