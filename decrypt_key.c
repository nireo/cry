#include <openssl/pem.h>
#include <stdlib.h>

#include "openssl/rsa.h"
#include "stdio.h"

const char* key_path = "./key.txt";

RSA* createRSAFromFile(char* filename, int public) {
    FILE* fp = fopen(filename, "rb");
    if (fp == NULL) {
        printf("Unable to open file %s \n", filename);
        return NULL;
    }

    RSA* rsa = RSA_new();
    if (public) {
        rsa = PEM_read_RSA_PUBKEY(fp, &rsa, NULL, NULL);
    } else {
        rsa = PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);
    }

    return rsa;
}

int main(void) {
    RSA* rsa = createRSAFromFile("./private-key.pem", 0);

    FILE* file = fopen(key_path, "r+");
    if (file == NULL) {
        printf("could not open the key file\n");
        exit(EXIT_FAILURE);
    }
    fseek(file, 0, SEEK_END);
    long int size = ftell(file);
    fclose(file);

    file = fopen(key_path, "r+");
    unsigned char* encrypted_data = (unsigned char*)malloc(size);
    int bytes_read = fread(encrypted_data, sizeof(unsigned char), size, file);
    fclose(file);

    char* decrypted_data = (char*)malloc(RSA_size(rsa));
    if (RSA_private_decrypt(size, (unsigned char*)encrypted_data, (unsigned char*)decrypted_data, rsa,
                            RSA_PKCS1_OAEP_PADDING) == -1) {
        printf("error decrypting data\n");
    }

    FILE* out = fopen("./dkey.txt", "w");
    fwrite(decrypted_data, sizeof(*decrypted_data), RSA_size(rsa), out);
    fclose(out);
    free(decrypted_data);
    free(encrypted_data);

    return EXIT_SUCCESS;
}
