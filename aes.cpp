#include "aes.hpp"
#include <string>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

std::string aes::bytes_to_str(const std::vector<uint8_t>& bytes) {
    return std::string(bytes.begin(), bytes.end());
}

void aes::encrypt(const std::vector<uint8_t> &key, const std::vector<uint8_t> &to_encrypt,
                  std::vector<uint8_t> &output) const {
    output.resize(to_encrypt.size() * AES_BLOCK_SIZE);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    int out_len = 0;
    size_t total = 0;

    EVP_EncryptInit(ctx, EVP_aes_256_cbc(), key.data(), m_iv.data());
    EVP_EncryptUpdate(ctx, output.data(), &out_len, to_encrypt.data(), to_encrypt.size());
    total += out_len;
    EVP_EncryptFinal(ctx, output.data()+total, &out_len);

    total += out_len;

    output.resize(total);
}
