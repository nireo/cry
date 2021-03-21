build:
	gcc main.c -lsodium -lcrypto -g -o cry

decryptkey:
	gcc decrypt_key.c -lcrypto -g -o decrypt_key

decryptfiles:
	gcc decrypt_files.c -lcrypto -lsodium -g -o decrypt_files

clean:
	rm -f main
