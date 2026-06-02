#include "../include/BelT.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

std::vector<uint8_t> BelT::ENCRYPTION_ECB(std::span<const uint8_t> input_bytes) {
    std::vector<uint8_t> output_bytes(input_bytes.size());

    const size_t len_last_block = input_bytes.size() % BLOCK_128_length;
    const size_t offset_last_block = (input_bytes.size() - len_last_block);

    if (len_last_block == 0) {
        for (uint8_t off = 0; off < input_bytes.size(); off += BLOCK_128_length) {
            auto word = bytes_to_u32x4_block(input_bytes.data() + off);
            auto encrypted_word = ENCRYPT_BLOCK(word);
            auto encrypted_bytes = u32x4_block_to_bytes(encrypted_word);
            std::copy(encrypted_bytes.begin(), encrypted_bytes.end(), output_bytes.begin() + off);
        }

        return output_bytes;
    }

    const size_t tail_offset = input_bytes.size() - len_last_block;
    const size_t penultimate_offset = tail_offset - BLOCK_128_length;

    for (size_t off = 0; off < penultimate_offset; off += BLOCK_128_length) {
        auto block = bytes_to_u32x4_block(input_bytes.data() + off);
        auto encrypted_block = ENCRYPT_BLOCK(block);
        auto encrypted_bytes = u32x4_block_to_bytes(encrypted_block);
        std::copy(encrypted_bytes.begin(), encrypted_bytes.end(), output_bytes.begin() + off);
    }

    auto penultimate_block = bytes_to_u32x4_block(input_bytes.data() + penultimate_offset);
    auto enc_penultimate_block = ENCRYPT_BLOCK(penultimate_block);
    auto enc_penultimate_bytes = u32x4_block_to_bytes(enc_penultimate_block);

    std::array<uint8_t, BLOCK_128_length> last_input_bytes {};
    for (size_t i = 0; i < len_last_block; ++i) {
        last_input_bytes[i] = input_bytes[offset_last_block + i];
    }
    for (size_t i = len_last_block; i < BLOCK_128_length; ++i) {
        last_input_bytes[i] = enc_penultimate_bytes[i];
    }

    auto last_block = bytes_to_u32x4_block(last_input_bytes.data());
    auto enc_last_block = ENCRYPT_BLOCK(last_block);
    auto enc_last_bytes = u32x4_block_to_bytes(enc_last_block);
    std::copy(enc_last_bytes.begin(), enc_last_bytes.end(), output_bytes.begin() + penultimate_offset);

    for (size_t i = 0; i < len_last_block; ++i) {
        output_bytes[tail_offset + i] = enc_penultimate_bytes[i];
    }

    return output_bytes;
}

std::vector<uint8_t> BelT::DECRYPTION_ECB(std::span<const uint8_t> input_bytes) {
    std::vector<uint8_t> output_bytes(input_bytes.size());

    const size_t len_last_block = input_bytes.size() % BLOCK_128_length;
    const size_t offset_last_block = (input_bytes.size() - len_last_block);

    if (len_last_block == 0) {
        for (uint8_t off = 0; off < input_bytes.size(); off += BLOCK_128_length) {
            auto word = bytes_to_u32x4_block(input_bytes.data() + off);
            auto encrypted_word = DECRYPT_BLOCK(word);
            auto encrypted_bytes = u32x4_block_to_bytes(encrypted_word);
            std::copy(encrypted_bytes.begin(), encrypted_bytes.end(), output_bytes.begin() + off);
        }

        return output_bytes;
    }

    const size_t tail_offset = input_bytes.size() - len_last_block;
    const size_t penultimate_offset = tail_offset - BLOCK_128_length;

    for (size_t off = 0; off < penultimate_offset; off += BLOCK_128_length) {
        auto block = bytes_to_u32x4_block(input_bytes.data() + off);
        auto encrypted_block = DECRYPT_BLOCK(block);
        auto encrypted_bytes = u32x4_block_to_bytes(encrypted_block);
        std::copy(encrypted_bytes.begin(), encrypted_bytes.end(), output_bytes.begin() + off);
    }

    auto penultimate_block = bytes_to_u32x4_block(input_bytes.data() + penultimate_offset);
    auto enc_penultimate_block = DECRYPT_BLOCK(penultimate_block);
    auto enc_penultimate_bytes = u32x4_block_to_bytes(enc_penultimate_block);

    std::array<uint8_t, 16> last_input_bytes {};
    for (size_t i = 0; i < len_last_block; ++i) {
        last_input_bytes[i] = input_bytes[offset_last_block + i];
    }
    for (size_t i = len_last_block; i < BLOCK_128_length; ++i) {
        last_input_bytes[i] = enc_penultimate_bytes[i];
    }

    auto last_block = bytes_to_u32x4_block(last_input_bytes.data());
    auto enc_last_block = DECRYPT_BLOCK(last_block);
    auto enc_last_bytes = u32x4_block_to_bytes(enc_last_block);
    std::copy(enc_last_bytes.begin(), enc_last_bytes.end(), output_bytes.begin() + penultimate_offset);

    for (size_t i = 0; i < len_last_block; ++i) {
        output_bytes[tail_offset + i] = enc_penultimate_bytes[i];
    }

    return output_bytes;
}
