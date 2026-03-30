#include "../include/BelT.h"
#include <array>
#include <cstdint>
#include <iomanip>
#include <vector>

uint32_t load_u32_be(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) |
           (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) << 8)  |
           uint32_t(p[3]);
}

void store_u32_be(uint8_t* p, uint32_t x) {
    p[0] = static_cast<uint8_t>(x >> 24);
    p[1] = static_cast<uint8_t>(x >> 16);
    p[2] = static_cast<uint8_t>(x >> 8);
    p[3] = static_cast<uint8_t>(x);
}

std::array<uint32_t, 4> read_block(const uint8_t* p) {
    return {
        load_u32_be(p + 0),
        load_u32_be(p + 4),
        load_u32_be(p + 8),
        load_u32_be(p + 12)
    };
}

void write_block(uint8_t* p, const std::array<uint32_t, 4>& block) {
    store_u32_be(p + 0,  block[0]);
    store_u32_be(p + 4,  block[1]);
    store_u32_be(p + 8,  block[2]);
    store_u32_be(p + 12, block[3]);
}

std::vector<uint8_t> BelT::ENCRYPTION_ECB(std::span<const uint8_t> input_bytes) {
    std::vector<uint8_t> output_bytes(input_bytes.size());

    for (size_t off = 0; off < input_bytes.size(); off += 16) {
        auto word = read_block(input_bytes.data() + off);

        auto encrypted_word = ENCRYPT_BLOCK(word);

        write_block(output_bytes.data() + off, encrypted_word);
    }

    return output_bytes;
}



std::vector<uint8_t> BelT::ENCRYPTION_CTR(std::span<const uint8_t> data,std::span<const uint8_t, 16> IV) {
    std::vector<uint8_t> out;
    return out;
}

std::vector<uint8_t> BelT::ENCRYPTION_MAC(std::span<const uint8_t> data) {
    std::vector<uint8_t> out;
    return out;
}


std::vector<uint8_t> BelT::DECRYPTION_ECB(std::span<const uint8_t> input_bytes) {
    std::vector<uint8_t> output_bytes(input_bytes.size());

    for (size_t off = 0; off < input_bytes.size(); off += 16) {
        auto word = read_block(input_bytes.data() + off);

        auto encrypted_word = DECRYPT_BLOCK(word);

        write_block(output_bytes.data() + off, encrypted_word);
    }

    return output_bytes;
}

std::vector<uint8_t> BelT::DECRYPTION_CTR(std::span<const uint8_t> data,std::span<const uint8_t, 16> IV) {
    return ENCRYPTION_CTR(data, IV);
}