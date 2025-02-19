# simple-ransomware

This code should only be used for educational purposes only.

Encryption_program,

Generates a 32-byte AES encryption key and a 16-byte Initialization Vector.
Saves them in a temporary directory as keyfile.bin.
Scans the user's home directory for files with specific extensions (.txt, .docx, .jpg, etc.).
Encrypts them using AES-256 in CBC mode, padding the content to a multiple of 16 bytes.
Saves the encrypted files with a new .ravi5hanka extension and deletes the original files.
Creates a text file containing a ransom note.
Opens it in Notepad to inform the user that their files have been encrypted.

