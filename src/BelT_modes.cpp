#include "../include/BelT.h"
#include <array>
#include <cstdint>

std::span<const uint8_t> BelT::ENCRYPTION_ECBNEW(std::span<const uint8_t> data) {
    std::array<uint32_t, 4> BLOCK;
    std::memcpy(BLOCK.data(), data.data(), 16);
    std::array<uint32_t, 4> CIPHER_BLOCK;

    CIPHER_BLOCK = ENCRYPT_BLOCK(BLOCK);

    std::span<const uint8_t> cipher_bytes(reinterpret_cast<const uint8_t*>(CIPHER_BLOCK.data()),sizeof(CIPHER_BLOCK));
    return cipher_bytes;
}

std::span<const uint8_t> BelT::ENCRYPTION_CTRNEW(std::span<const uint8_t> data,std::span<const uint8_t, 16> IV) {

}

std::span<const uint8_t> BelT::ENCRYPTION_MACNEW(std::span<const uint8_t> data) {

}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

std::string BelT::ENCRYPTION_ECB(const std::string& plaintext) {
    if (plaintext.size() < BLOCK_128_length) {
        throw std::invalid_argument("Incorrect text size");
    }

    std::vector<std::string> blocks_128b = SplitTo128(plaintext);

    uint32_t num_of_blocks = blocks_128b.size();
    uint8_t length_last_block = plaintext.size() % 16;

    std::string ciphertext;
    for (uint32_t i = 0; i < num_of_blocks; ++i) {
        if (length_last_block != 0 && i == num_of_blocks - 2) {
            std::string enc_last_block = ENCRYPT_ONE_BLOCK(blocks_128b[i]);
            std::string r = enc_last_block.substr(length_last_block, 16 - length_last_block);
            enc_last_block = enc_last_block.substr(0, length_last_block);

            ciphertext += ENCRYPT_ONE_BLOCK(blocks_128b[i + 1] + r);
            ciphertext += enc_last_block;
            break;
        }
        ciphertext += ENCRYPT_ONE_BLOCK(blocks_128b[i]);
    }
    return ciphertext;
}
std::string BelT::ENCRYPTION_CTR(const std::string& plaintext, const std::string& iv) {
    if (plaintext.size() < BLOCK_128_length) {
        throw std::invalid_argument("Incorrect text size");
    }
    // Проверка размера IV (синхропосылки)
    if (iv.size() != IV_128_length) {
        throw std::invalid_argument("IV must be 128 bits");
    }

    // Разбиваем текст на блоки по 16 байт
    std::vector<std::string> blocks = SplitTo128(plaintext);
    std::string ciphertext;

    // Инициализируем s = belt-block(S, K)
    std::string s = ENCRYPT_ONE_BLOCK(iv);

    for (size_t i = 0; i < blocks.size(); ++i) {
        // 1. s = s + 1 (инкремент 128-битного числа)
        for (int j = 0; j <= 15; ++j) {
            if (++s[j] != 0) break; // Учитываем перенос
        }

        // 2. Шифруем текущее значение s
        std::string encrypted_s = ENCRYPT_ONE_BLOCK(s);

        // 3. Берем нужное количество байт (|X_i|)
        size_t block_size = blocks[i].size();
        std::string keystream = encrypted_s.substr(0, block_size);

        // 4. XOR с исходным блоком
        std::string encrypted_block;
        for (size_t j = 0; j < block_size; ++j) {
            encrypted_block += blocks[i][j] ^ keystream[j];
        }

        ciphertext += encrypted_block;
    }

    return ciphertext;
}
std::string BelT::ENCRYPTION_MAC(const std::string& data) {
    std::vector<std::string> blocks = SplitTo128(data);

    std::string s(16, '\x00');
    std::string r = ENCRYPT_ONE_BLOCK(s);

    for (size_t i = 0; i < blocks.size() - 1; ++i) {
        s = xor_strings(s, blocks[i]);
        s = ENCRYPT_ONE_BLOCK(s);
    }

    std::string last_block = blocks.back();
    if (last_block.size() == 16) {
        s = xor_strings(s, xor_strings(last_block, phi1(r)));
    }
    else {
        s = xor_strings(s, xor_strings(psi(last_block), phi2(r)));
    }

    std::string tag = ENCRYPT_ONE_BLOCK(s);
    return tag.substr(0, 8); // Первые 64 бита
}

std::string BelT::DECRYPTION_ECB(const std::string& text_encrypted) {
    // Check size of text_encrypted >= 128 bit
    if (text_encrypted.size() < BLOCK_128_length) {
        throw std::invalid_argument("Incorrect ciphertext size");
    }

    std::vector<std::string> blocks_128b = SplitTo128(text_encrypted);

    uint32_t num_blocks = blocks_128b.size();
    uint8_t length_last_block = text_encrypted.size() % 16;

    std::string text;
    for (uint32_t i = 0; i < num_blocks; ++i) {
        if (length_last_block != 0 && i == num_blocks - 2) {
            std::string enc_last_block = DECRYPT_ONE_BLOCK(blocks_128b[i]);
            std::string r = enc_last_block.substr(length_last_block, 16 - length_last_block);
            enc_last_block = enc_last_block.substr(0, length_last_block);

            text += DECRYPT_ONE_BLOCK(blocks_128b[i + 1] + r);
            text += enc_last_block;
            break;
        }
        text += DECRYPT_ONE_BLOCK(blocks_128b[i]);
    }
    return text;
}
// Для CTR режима шифрование и дешифрование одинаковы
std::string BelT::DECRYPTION_CTR(const std::string& ciphertext, const std::string& iv) {
    return ENCRYPTION_CTR(ciphertext, iv);
}