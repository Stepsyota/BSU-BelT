#include "../include/BelT.h"

#include <algorithm>

std::array<uint8_t, BLOCK_128_length> BelT::xor_blocks(
    const std::array<uint8_t, BLOCK_128_length>& left,
    const std::array<uint8_t, BLOCK_128_length>& right
) {
    std::array<uint8_t, BLOCK_128_length> result{};
    for (std::size_t index = 0; index < BLOCK_128_length; ++index) {
        result[index] = left[index] ^ right[index];
    }
    return result;
}

std::array<uint8_t, BLOCK_128_length> BelT::increment_counter(std::array<uint8_t, BLOCK_128_length> value) {
    for (std::size_t index = 0; index < BLOCK_128_length; ++index) {
        if (++value[index] != 0) {
            break;
        }
    }
    return value;
}

std::array<uint8_t, BLOCK_128_length> BelT::pad_mac_block(std::span<const uint8_t> tail) {
    std::array<uint8_t, BLOCK_128_length> padded{};
    std::copy(tail.begin(), tail.end(), padded.begin());
    if (tail.size() < BLOCK_128_length) {
        padded[tail.size()] = 0x80;
    }
    return padded;
}

std::array<uint8_t, 16> BelT::phi1(const std::array<uint8_t, 16>& r) {
    auto words = std::array<uint32_t, 4>{
        (uint32_t(r[0]) << 24) | (uint32_t(r[1]) << 16) | (uint32_t(r[2]) << 8) | uint32_t(r[3]),
        (uint32_t(r[4]) << 24) | (uint32_t(r[5]) << 16) | (uint32_t(r[6]) << 8) | uint32_t(r[7]),
        (uint32_t(r[8]) << 24) | (uint32_t(r[9]) << 16) | (uint32_t(r[10]) << 8) | uint32_t(r[11]),
        (uint32_t(r[12]) << 24) | (uint32_t(r[13]) << 16) | (uint32_t(r[14]) << 8) | uint32_t(r[15]),
    };

    const uint32_t tail = words[0] ^ words[1];
    const std::array<uint32_t, 4> transformed{words[1], words[2], words[3], tail};

    return {
        uint8_t(transformed[0] >> 24), uint8_t(transformed[0] >> 16), uint8_t(transformed[0] >> 8), uint8_t(transformed[0]),
        uint8_t(transformed[1] >> 24), uint8_t(transformed[1] >> 16), uint8_t(transformed[1] >> 8), uint8_t(transformed[1]),
        uint8_t(transformed[2] >> 24), uint8_t(transformed[2] >> 16), uint8_t(transformed[2] >> 8), uint8_t(transformed[2]),
        uint8_t(transformed[3] >> 24), uint8_t(transformed[3] >> 16), uint8_t(transformed[3] >> 8), uint8_t(transformed[3]),
    };
}

std::array<uint8_t, 16> BelT::phi2(const std::array<uint8_t, 16>& r) {
    auto words = std::array<uint32_t, 4>{
        (uint32_t(r[0]) << 24) | (uint32_t(r[1]) << 16) | (uint32_t(r[2]) << 8) | uint32_t(r[3]),
        (uint32_t(r[4]) << 24) | (uint32_t(r[5]) << 16) | (uint32_t(r[6]) << 8) | uint32_t(r[7]),
        (uint32_t(r[8]) << 24) | (uint32_t(r[9]) << 16) | (uint32_t(r[10]) << 8) | uint32_t(r[11]),
        (uint32_t(r[12]) << 24) | (uint32_t(r[13]) << 16) | (uint32_t(r[14]) << 8) | uint32_t(r[15]),
    };

    const uint32_t head = words[0] ^ words[3];
    const std::array<uint32_t, 4> transformed{head, words[0], words[1], words[2]};

    return {
        uint8_t(transformed[0] >> 24), uint8_t(transformed[0] >> 16), uint8_t(transformed[0] >> 8), uint8_t(transformed[0]),
        uint8_t(transformed[1] >> 24), uint8_t(transformed[1] >> 16), uint8_t(transformed[1] >> 8), uint8_t(transformed[1]),
        uint8_t(transformed[2] >> 24), uint8_t(transformed[2] >> 16), uint8_t(transformed[2] >> 8), uint8_t(transformed[2]),
        uint8_t(transformed[3] >> 24), uint8_t(transformed[3] >> 16), uint8_t(transformed[3] >> 8), uint8_t(transformed[3]),
    };
}
