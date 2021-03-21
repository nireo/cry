# cry: A proof-of-concept ransomware

Cry is a proof-of-concept ransomware written for Linux.

## Running

This section provides the setup instructions, for complete operation refer to `How it works`. You need to create a RSA keypair using the `gen_keys.sh`. After that you need to run the `create_embed_key.sh` and add the `public-key.c` to the main.c file. After that the setup is done.

## Disclaimer

This project is purely academic, use at your own risk. I do not encourage in any way the use of this software illegally or to attack targets without their previous authorization.

**cry** is an academic ransomware made to learn about cryptography and security.

## How it works

Libsodium creates a cryptographically secure 32-bit key for encryption. The encryption used for files is xchacha20poly1305. After that the encryption is encrypted using the embedded RSA public-key in the `main.c` file. The resulting encrypted key will be written into a file called `key.txt`.

The decryption process is quite simple. You compile the `decrypt_key.c` file and that gives you a `dkey.txt`. After this compiling and running the `decrypt_files.c` will decrypt all of the files using the decrypted encryption key.

## Compiling

All the compilation instructions can be found in the `Makefile` and can also be easily made using `make`.
