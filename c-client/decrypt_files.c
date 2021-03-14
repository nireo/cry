#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <stdlib.h>

#include "dirent.h"
#include "sodium.h"
#include "stdio.h"
#include "string.h"

#define CHUNK_SIZE 4096

static int decrypt(const char *to_encrypt, const char *source_file,
                   const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]) {
    unsigned char buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char buf_out[CHUNK_SIZE];
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    FILE *fp_t, *fp_s;
    unsigned long long out_len;
    size_t rlen;
    int eof;
    int ret = -1;
    unsigned char tag;

    fp_s = fopen(source_file, "rb");
    fp_t = fopen(to_encrypt, "wb");
    fread(header, 1, sizeof header, fp_s);
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
        goto ret;
    }
    do {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);
        if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag, buf_in, rlen, NULL, 0) !=
            0) {
            goto ret;
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && !eof) {
            goto ret;
        }
        fwrite(buf_out, 1, (size_t)out_len, fp_t);
    } while (!eof);

    ret = 0;
ret:
    fclose(fp_t);
    fclose(fp_s);
    return ret;
}

// remove extension takes away the .ccry extension from a filename
char *remove_extension(char *s) {
    int n;
    int i;
    char *new;
    for (i = 0; s[i] != '\0'; i++)
        ;
    n = i - 5 + 1;
    if (n < 1)
        return NULL;
    new = (char *)malloc(n * sizeof(char));
    for (i = 0; i < n - 1; i++)
        new[i] = s[i];
    new[i] = '\0';
    return new;
}

const char *root_dir_path = "./test";

int main(void) {
    DIR *root_dir = opendir(root_dir_path);
    struct dirent *dir;

    char *to_decrypt[512];
    int i = 0;
    if (root_dir) {
        while ((dir = readdir(root_dir)) != NULL) {
            if (!strcmp(dir->d_name, ".") || !strcmp(dir->d_name, "..")) {
                // for some reason c prints out these two so just skip them
                continue;
            }

            printf("decrypting %s...\n", dir->d_name);
            to_decrypt[i] = dir->d_name;
            ++i;
        }
        closedir(root_dir);
    }

    FILE *file = fopen("./dkey.txt", "r+");
    if (file == NULL)
        exit(EXIT_FAILURE);
    fseek(file, 0, SEEK_END);
    long int size = ftell(file);
    fclose(file);
    file = fopen("./dkey.txt", "r+");
    unsigned char *key = (unsigned char *)malloc(size);
    int bytes_read = fread(key, sizeof(unsigned char), size, file);
    fclose(file);

    // check that the key is of the correct size
    if (sizeof(key) != crypto_secretstream_xchacha20poly1305_KEYBYTES) {
        exit(EXIT_FAILURE);
    }

    for (int j = 0; j < i; ++j) {
        char *new_file_name = remove_extension(to_decrypt[j]);

        if (decrypt(new_file_name, to_decrypt[j], key) != 0)
            printf("error decryping file %s\n", to_decrypt[j]);
    }

    printf("All of your files have now beed decrypted have fun...\n");

    return EXIT_SUCCESS;
}
