#ifndef CCRY_AES_HPP
#define CCRY_AES_HPP

#include <vector>
#include <cstdint>
#include <string>
#include <openssl/rand.h>


class aes {
private:
    std::vector<uint8_t> m_iv;

public:
    explicit aes() {
        unsigned char iv_buffer[16];
        RAND_bytes(iv_buffer, sizeof(iv_buffer));
        m_iv = std::vector<uint8_t> (iv_buffer, iv_buffer + 16);
    }

    void encrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& to_encrypt,
                 std::vector<uint8_t>& output) const;

    static std::string bytes_to_str(const std::vector<uint8_t>& bytes);
};



#endif //CCRY_AES_HPP
