build:
	gcc main.c -lsodium -lcrypto -g

decryptkey:
	gcc decrypt_key.c -lcrypto -g

decryptfiles:
	gcc decrypt_files.c -lcrypto -lsodium -g

clean:
	rm -f main
