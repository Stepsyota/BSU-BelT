#include "../include/BelT.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>


std::vector<uint8_t> BelT::ENCRYPTION_ECB(std::span<const uint8_t> input_bytes) {
    std::vector<uint8_t> output_bytes(input_bytes.size());

    const size_t len_last_block = input_bytes.size() % 16;
    const size_t offset_last_block = (input_bytes.size() - len_last_block);

    if (len_last_block == 0) {
        for (uint8_t off = 0; off < input_bytes.size(); off += 16) {
            auto word = bytes_to_u32x4_block(input_bytes.data() + off);

            auto encrypted_word = ENCRYPT_BLOCK(word);

            auto encrypted_bytes = u32x4_block_to_bytes(encrypted_word);
            std::copy(encrypted_bytes.begin(), encrypted_bytes.end(),output_bytes.begin() + off);
        }

        return output_bytes;
    }

    const size_t tail_offset  = input_bytes.size() - len_last_block;
    const size_t penultimate_offset  = tail_offset - 16;
    
    for (size_t off = 0; off < penultimate_offset; off += 16) {
        auto block = bytes_to_u32x4_block(input_bytes.data() + off);

        auto encrypted_block = ENCRYPT_BLOCK(block);

        auto encrypted_bytes = u32x4_block_to_bytes(encrypted_block);
        std::copy(encrypted_bytes.begin(), encrypted_bytes.end(),output_bytes.begin() + off);
    }

    auto penultimate_block = bytes_to_u32x4_block(input_bytes.data() + penultimate_offset);
    auto enc_penultimate_block = ENCRYPT_BLOCK(penultimate_block);
    auto enc_penultimate_bytes = u32x4_block_to_bytes(enc_penultimate_block);

    std::array<uint8_t, 16> last_input_bytes {};
    for (size_t i = 0; i < len_last_block; ++i) {
        last_input_bytes[i] = input_bytes[offset_last_block + i];
    }
    for (size_t i = len_last_block; i < 16; ++i) {
        last_input_bytes[i] = enc_penultimate_bytes[i];
    }

    auto last_block = bytes_to_u32x4_block(last_input_bytes.data());
    auto enc_last_block = ENCRYPT_BLOCK(last_block);
    auto enc_last_bytes = u32x4_block_to_bytes(enc_last_block);
    std::copy(enc_last_bytes.begin(), enc_last_bytes.end(),output_bytes.begin() + penultimate_offset);

    for (size_t i = 0; i < len_last_block; ++i) {
        output_bytes[tail_offset + i] = enc_penultimate_bytes[i];
    }

    return output_bytes;
}

std::vector<uint8_t> BelT::DECRYPTION_ECB(std::span<const uint8_t> input_bytes) {
    std::vector<uint8_t> output_bytes(input_bytes.size());

    const size_t len_last_block = input_bytes.size() % 16;
    const size_t offset_last_block = (input_bytes.size() - len_last_block);

    if (len_last_block == 0) {
        for (uint8_t off = 0; off < input_bytes.size(); off += 16) {
            auto word = bytes_to_u32x4_block(input_bytes.data() + off);

            auto encrypted_word = DECRYPT_BLOCK(word);

            auto encrypted_bytes = u32x4_block_to_bytes(encrypted_word);
            std::copy(encrypted_bytes.begin(), encrypted_bytes.end(),output_bytes.begin() + off);
        }

        return output_bytes;
    }

    const size_t tail_offset  = input_bytes.size() - len_last_block;
    const size_t penultimate_offset  = tail_offset - 16;
    
    for (size_t off = 0; off < penultimate_offset; off += 16) {
        auto block = bytes_to_u32x4_block(input_bytes.data() + off);

        auto encrypted_block = DECRYPT_BLOCK(block);

        auto encrypted_bytes = u32x4_block_to_bytes(encrypted_block);
        std::copy(encrypted_bytes.begin(), encrypted_bytes.end(),output_bytes.begin() + off);
    }

    auto penultimate_block = bytes_to_u32x4_block(input_bytes.data() + penultimate_offset);
    auto enc_penultimate_block = DECRYPT_BLOCK(penultimate_block);
    auto enc_penultimate_bytes = u32x4_block_to_bytes(enc_penultimate_block);

    std::array<uint8_t, 16> last_input_bytes {};
    for (size_t i = 0; i < len_last_block; ++i) {
        last_input_bytes[i] = input_bytes[offset_last_block + i];
    }
    for (size_t i = len_last_block; i < 16; ++i) {
        last_input_bytes[i] = enc_penultimate_bytes[i];
    }

    auto last_block = bytes_to_u32x4_block(last_input_bytes.data());
    auto enc_last_block = DECRYPT_BLOCK(last_block);
    auto enc_last_bytes = u32x4_block_to_bytes(enc_last_block);
    std::copy(enc_last_bytes.begin(), enc_last_bytes.end(),output_bytes.begin() + penultimate_offset);

    for (size_t i = 0; i < len_last_block; ++i) {
        output_bytes[tail_offset + i] = enc_penultimate_bytes[i];
    }
    
    return output_bytes;
}


//     for (size_t i = 0; i < blocks.size(); ++i) {
//         // 1. s = s + 1 (инкремент 128-битного числа)
//         for (int j = 0; j <= 15; ++j) {
//             if (++s[j] != 0) break; // Учитываем перенос
//         }

//         // 2. Шифруем текущее значение s
//         std::string encrypted_s = ENCRYPT_ONE_BLOCK(s);

//         // 3. Берем нужное количество байт (|X_i|)
//         size_t block_size = blocks[i].size();
//         std::string keystream = encrypted_s.substr(0, block_size);


std::vector<uint8_t> BelT::ENCRYPTION_CTR(std::span<const uint8_t> input_bytes,std::span<const uint8_t, 16> IV) {
    std::vector<uint8_t> output_bytes(input_bytes.size());

    // auto init_vector = read_block(IV.data());
    // auto encrypted_init_vector = ENCRYPT_BLOCK(init_vector);

    // for (size_t off = 0; off < input_bytes.size(); off += 16) {
    //     auto word = read_block(input_bytes.data() + off);

    //     std::array<uint32_t, 4> encrypted_word;
    //     for (auto i : encrypted_word) {
    //         encrypted_word[i] = word[i] ^ encrypted_init_vector[i]; 
    //     }

    //     write_block(output_bytes.data() + off, encrypted_word);
    // }

    return output_bytes;
}

std::vector<uint8_t> BelT::DECRYPTION_CTR(std::span<const uint8_t> data,std::span<const uint8_t, 16> IV) {
    return ENCRYPTION_CTR(data, IV);
}

std::vector<uint8_t> BelT::ENCRYPTION_MAC(std::span<const uint8_t> data) {
    std::vector<uint8_t> out;
    return out;
}