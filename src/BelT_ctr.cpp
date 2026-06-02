#include "../include/BelT.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

std::array<uint8_t, 16> BelT::increment_counter32(std::array<uint8_t, 16> value) {
    for (std::size_t index = 16; index-- > 12;) {
        if (++value[index] != 0) {
            break;
        }
    }
    return value;
}

std::vector<uint8_t> BelT::counter_crypt(std::span<const uint8_t> data, std::array<uint8_t, 16> counter, bool gcm_style) {
    std::vector<uint8_t> result(data.size());
    if (data.empty()) {
        return result;
    }

    const std::size_t blocks_count = (data.size() + 15) / 16;

    for (std::size_t block_index = 0; block_index < blocks_count; ++block_index) {
        counter = gcm_style ? increment_counter32(counter) : increment_counter(counter);
        const auto encrypted_counter = u32x4_block_to_bytes(ENCRYPT_BLOCK(bytes_to_u32x4_block(counter.data())));
        const std::size_t offset = block_index * 16;
        const std::size_t block_size = std::min<std::size_t>(16, data.size() - offset);

        for (std::size_t i = 0; i < block_size; ++i) {
            result[offset + i] = data[offset + i] ^ encrypted_counter[i];
        }
    }

    return result;
}

std::vector<uint8_t> BelT::CTR_CRYPT(std::span<const uint8_t> data, std::span<const uint8_t, 16> iv) {
    std::vector<uint8_t> result(data.size());
    if (data.empty()) {
        return result;
    }

    std::array<uint8_t, 16> s = u32x4_block_to_bytes(ENCRYPT_BLOCK(bytes_to_u32x4_block(iv.data())));
    const std::size_t blocks_count = (data.size() + 15) / 16;

    for (std::size_t block_index = 0; block_index < blocks_count; ++block_index) {
        for (std::size_t byte_index = 0; byte_index < 16; ++byte_index) {
            if (++s[byte_index] != 0) {
                break;
            }
        }

        const auto encrypted_s = u32x4_block_to_bytes(ENCRYPT_BLOCK(bytes_to_u32x4_block(s.data())));
        const std::size_t offset = block_index * 16;
        const std::size_t block_size = std::min<std::size_t>(16, data.size() - offset);

        for (std::size_t i = 0; i < block_size; ++i) {
            result[offset + i] = data[offset + i] ^ encrypted_s[i];
        }
    }

    return result;
}

std::vector<uint8_t> BelT::ENCRYPTION_CTR(std::span<const uint8_t> plaintext, std::span<const uint8_t, 16> iv) {
    if (plaintext.size() < BLOCK_128_length) {
        throw std::invalid_argument("Incorrect text size");
    }

    return CTR_CRYPT(plaintext, iv);
}

std::vector<uint8_t> BelT::DECRYPTION_CTR(std::span<const uint8_t> data, std::span<const uint8_t, 16> IV) {
    if (data.size() < BLOCK_128_length) {
        throw std::invalid_argument("Incorrect text size");
    }

    return CTR_CRYPT(data, IV);
}
