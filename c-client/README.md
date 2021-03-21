# ccry: A proof-of-concept ransomware

Ccry is a proof-of-concept ransomware written for Linux.

## How it works

Libsodium creates a cryptographically secure 32-bit key for encryption. The encryption used for files is xchacha20poly1305. After that the encryption is encrypted using the embedded RSA public-key in the `main.c` file. The resulting encrypted key will be written into a file called `key.txt`.

The decryption process is quite simple. You compile the `decrypt_key.c` file and that gives you a `dkey.txt`. After this compiling and running the `decrypt_files.c` will decrypt all of the files using the decrypted encryption key.

