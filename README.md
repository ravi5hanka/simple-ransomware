# simple-ransomware

Encryption program,

Generates a 32-byte AES encryption key and a 16-byte Initialization Vector.

Saves them in a temporary directory as keyfile.bin.

Scans the user's home directory for files with specific extensions (.txt, .docx, .jpg, etc.).

Encrypts them using AES-256 in CBC mode, padding the content to a multiple of 16 bytes.

Saves the encrypted files with a new .ravi5hanka extension and deletes the original files.

Creates a text file containing a ransom note.

Opens it in Notepad to inform the user that their files have been encrypted.


Decryption program,

Retrieves the previously saved AES encryption key and IV from the system's temporary directory (keyfile.bin).

If the key file is missing, it exits without proceeding.

Searches for encrypted files with the .ravi5hanka extension in the user's home directory.

Reads the file’s content, extracts the IV (first 16 bytes), and decrypts the rest using AES-256 in CBC mode.

Removes padding and restores the original file, removing the .ravi5hanka extension.

Deletes the encrypted version after successful decryption.

After decrypting all files, it opens a Notepad window with a message stating that files have been decrypted.


Ethical Warning,

Running these scripts outside of a controlled environment can be illegal and harmful. These codes should be used for educational purposes only.

