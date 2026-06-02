#include "../include/BelT.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace {
constexpr std::size_t ccm_tag_size = 8;

std::array<uint8_t, 8> encode_u64_be(std::size_t value) {
    const auto as_u64 = static_cast<uint64_t>(value);
    return {
        static_cast<uint8_t>(as_u64 >> 56),
        static_cast<uint8_t>(as_u64 >> 48),
        static_cast<uint8_t>(as_u64 >> 40),
        static_cast<uint8_t>(as_u64 >> 32),
        static_cast<uint8_t>(as_u64 >> 24),
        static_cast<uint8_t>(as_u64 >> 16),
        static_cast<uint8_t>(as_u64 >> 8),
        static_cast<uint8_t>(as_u64),
    };
}

bool constant_time_equal(std::span<const uint8_t> left, std::span<const uint8_t> right) {
    if (left.size() != right.size()) {
        return false;
    }

    uint8_t diff = 0;
    for (std::size_t index = 0; index < left.size(); ++index) {
        diff |= static_cast<uint8_t>(left[index] ^ right[index]);
    }
    return diff == 0;
}
}

std::vector<uint8_t> BelT::ENCRYPTION_CCM(std::span<const uint8_t> data, std::span<const uint8_t, 16> IV) {
    const auto ciphertext = CTR_CRYPT(data, IV);

    std::vector<uint8_t> auth_input;
    auth_input.reserve(IV.size() + sizeof(uint64_t) + ciphertext.size());
    auth_input.insert(auth_input.end(), IV.begin(), IV.end());

    const auto length_bytes = encode_u64_be(ciphertext.size());
    auth_input.insert(auth_input.end(), length_bytes.begin(), length_bytes.end());
    auth_input.insert(auth_input.end(), ciphertext.begin(), ciphertext.end());

    const auto tag = ENCRYPTION_MAC(auth_input);

    std::vector<uint8_t> result;
    result.reserve(ciphertext.size() + tag.size());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    result.insert(result.end(), tag.begin(), tag.end());
    return result;
}

std::vector<uint8_t> BelT::DECRYPTION_CCM(std::span<const uint8_t> data, std::span<const uint8_t, 16> IV) {
    if (data.size() < ccm_tag_size) {
        throw std::invalid_argument("Incorrect text size");
    }

    const std::size_t ciphertext_size = data.size() - ccm_tag_size;
    std::span<const uint8_t> ciphertext(data.data(), ciphertext_size);
    std::span<const uint8_t> received_tag(data.data() + ciphertext_size, ccm_tag_size);

    std::vector<uint8_t> auth_input;
    auth_input.reserve(IV.size() + sizeof(uint64_t) + ciphertext.size());
    auth_input.insert(auth_input.end(), IV.begin(), IV.end());

    const auto length_bytes = encode_u64_be(ciphertext.size());
    auth_input.insert(auth_input.end(), length_bytes.begin(), length_bytes.end());
    auth_input.insert(auth_input.end(), ciphertext.begin(), ciphertext.end());

    const auto expected_tag = ENCRYPTION_MAC(auth_input);
    if (!constant_time_equal(received_tag, expected_tag)) {
        throw std::runtime_error("CCM authentication failed");
    }

    return CTR_CRYPT(ciphertext, IV);
}
