#include "../include/BelT.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace {
constexpr std::size_t gcm_tag_size = 16;

std::array<uint8_t, 8> encode_u64_be(uint64_t value) {
    return {
        static_cast<uint8_t>(value >> 56),
        static_cast<uint8_t>(value >> 48),
        static_cast<uint8_t>(value >> 40),
        static_cast<uint8_t>(value >> 32),
        static_cast<uint8_t>(value >> 24),
        static_cast<uint8_t>(value >> 16),
        static_cast<uint8_t>(value >> 8),
        static_cast<uint8_t>(value),
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

std::array<uint8_t, 16> make_block(std::span<const uint8_t> input) {
    std::array<uint8_t, 16> block{};
    std::copy(input.begin(), input.end(), block.begin());
    return block;
}

std::array<uint8_t, 16> make_len_block(std::size_t aad_size, std::size_t ciphertext_size) {
    const auto aad_bits = encode_u64_be(static_cast<uint64_t>(aad_size) * 8U);
    const auto ciphertext_bits = encode_u64_be(static_cast<uint64_t>(ciphertext_size) * 8U);
    return {
        aad_bits[0], aad_bits[1], aad_bits[2], aad_bits[3], aad_bits[4], aad_bits[5], aad_bits[6], aad_bits[7],
        ciphertext_bits[0], ciphertext_bits[1], ciphertext_bits[2], ciphertext_bits[3], ciphertext_bits[4], ciphertext_bits[5], ciphertext_bits[6], ciphertext_bits[7]
    };
}

void shift_right_one(std::array<uint8_t, 16>& value) {
    uint8_t carry = 0;
    for (std::size_t index = 0; index < 16; ++index) {
        const uint8_t next_carry = static_cast<uint8_t>(value[index] & 0x01U);
        value[index] = static_cast<uint8_t>((value[index] >> 1) | static_cast<uint8_t>(carry << 7));
        carry = next_carry;
    }
}
}

std::array<uint8_t, 16> BelT::gf_mul(
    const std::array<uint8_t, 16>& left,
    const std::array<uint8_t, 16>& right
) {
    std::array<uint8_t, 16> z{};
    std::array<uint8_t, 16> v = right;

    for (std::size_t bit_index = 0; bit_index < 128; ++bit_index) {
        const std::size_t byte_index = bit_index / 8;
        const uint8_t bit_mask = static_cast<uint8_t>(0x80U >> (bit_index % 8U));
        if ((left[byte_index] & bit_mask) != 0) {
            z = xor_blocks(z, v);
        }

        const bool lsb_set = (v[15] & 0x01U) != 0;
        shift_right_one(v);
        if (lsb_set) {
            v[0] ^= 0xE1U;
        }
    }

    return z;
}

std::array<uint8_t, 16> BelT::gcm_auth(
    std::span<const uint8_t> aad,
    std::span<const uint8_t> ciphertext,
    const std::array<uint8_t, 16>& hash_subkey
) {
    std::array<uint8_t, 16> y{};

    const std::size_t aad_blocks = (aad.size() + 15) / 16;
    for (std::size_t block_index = 0; block_index < aad_blocks; ++block_index) {
        const std::size_t offset = block_index * 16;
        const std::size_t block_size = std::min<std::size_t>(16, aad.size() - offset);
        auto block = make_block(aad.subspan(offset, block_size));
        y = gf_mul(xor_blocks(y, block), hash_subkey);
    }

    const std::size_t ciphertext_blocks = (ciphertext.size() + 15) / 16;
    for (std::size_t block_index = 0; block_index < ciphertext_blocks; ++block_index) {
        const std::size_t offset = block_index * 16;
        const std::size_t block_size = std::min<std::size_t>(16, ciphertext.size() - offset);
        auto block = make_block(ciphertext.subspan(offset, block_size));
        y = gf_mul(xor_blocks(y, block), hash_subkey);
    }

    const auto len_block = make_len_block(aad.size(), ciphertext.size());
    return gf_mul(xor_blocks(y, len_block), hash_subkey);
}

std::array<uint8_t, 16> BelT::gcm_finalize_tag(
    const std::array<uint8_t, 16>& ghash,
    const std::array<uint8_t, 16>& e_j0
) {
    return xor_blocks(ghash, e_j0);
}

std::array<uint8_t, 16> BelT::gcm_derive_j0(
    const std::array<uint8_t, 16>& hash_subkey,
    std::span<const uint8_t> nonce
) {
    if (nonce.size() == 12) {
        std::array<uint8_t, 16> j0{};
        std::copy(nonce.begin(), nonce.end(), j0.begin());
        j0[15] = 0x01U;
        return j0;
    }

    return gcm_auth(std::span<const uint8_t>{}, nonce, hash_subkey);
}

std::vector<uint8_t> BelT::gcm_ctr(
    std::span<const uint8_t> data,
    std::span<const uint8_t> nonce,
    const std::array<uint8_t, 16>& hash_subkey
) {
    const auto j0 = gcm_derive_j0(hash_subkey, nonce);
    return counter_crypt(data, j0, true);
}

std::vector<uint8_t> BelT::gcm_encrypt(
    std::span<const uint8_t> data,
    std::span<const uint8_t> nonce,
    std::optional<std::span<const uint8_t>> aad
) {
    const std::array<uint8_t, 16> zero_block{};
    const auto hash_subkey = u32x4_block_to_bytes(ENCRYPT_BLOCK(bytes_to_u32x4_block(zero_block.data())));
    const std::span<const uint8_t> aad_span = aad.value_or(std::span<const uint8_t>{});
    const auto j0 = gcm_derive_j0(hash_subkey, nonce);
    const auto ciphertext = gcm_ctr(data, nonce, hash_subkey);
    const auto ghash = gcm_auth(aad_span, ciphertext, hash_subkey);
    const auto e_j0 = u32x4_block_to_bytes(ENCRYPT_BLOCK(bytes_to_u32x4_block(j0.data())));
    const auto tag = gcm_finalize_tag(ghash, e_j0);

    std::vector<uint8_t> result;
    result.reserve(ciphertext.size() + tag.size());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    result.insert(result.end(), tag.begin(), tag.end());
    return result;
}

std::vector<uint8_t> BelT::gcm_decrypt(
    std::span<const uint8_t> data,
    std::span<const uint8_t> nonce,
    std::optional<std::span<const uint8_t>> aad
) {
    if (data.size() < gcm_tag_size) {
        throw std::invalid_argument("Incorrect text size");
    }

    const std::array<uint8_t, 16> zero_block{};
    const auto hash_subkey = u32x4_block_to_bytes(ENCRYPT_BLOCK(bytes_to_u32x4_block(zero_block.data())));
    const std::span<const uint8_t> aad_span = aad.value_or(std::span<const uint8_t>{});
    const std::size_t ciphertext_size = data.size() - gcm_tag_size;
    std::span<const uint8_t> ciphertext(data.data(), ciphertext_size);
    std::span<const uint8_t> received_tag(data.data() + ciphertext_size, gcm_tag_size);
    const auto j0 = gcm_derive_j0(hash_subkey, nonce);
    const auto ghash = gcm_auth(aad_span, ciphertext, hash_subkey);
    const auto e_j0 = u32x4_block_to_bytes(ENCRYPT_BLOCK(bytes_to_u32x4_block(j0.data())));
    const auto expected_tag = gcm_finalize_tag(ghash, e_j0);

    if (!constant_time_equal(received_tag, expected_tag)) {
        throw std::runtime_error("GCM authentication failed");
    }

    return gcm_ctr(ciphertext, nonce, hash_subkey);
}
