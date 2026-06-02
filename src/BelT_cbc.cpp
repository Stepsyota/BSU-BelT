#include "../include/BelT.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace {
constexpr std::size_t block_size = BLOCK_128_length;
}

std::vector<uint8_t> BelT::ENCRYPTION_CBC(std::span<const uint8_t> input_bytes, std::span<const uint8_t, 16> S) {
    if (input_bytes.size() < block_size) {
        throw std::invalid_argument("Incorrect text size");
    }

    std::vector<uint8_t> output_bytes(input_bytes.size());
    const std::size_t full_blocks = input_bytes.size() / block_size;
    const std::size_t tail_size = input_bytes.size() % block_size;

    std::array<uint8_t, block_size> previous_block{};
    std::copy(S.begin(), S.end(), previous_block.begin());

    if (tail_size == 0) {
        for (std::size_t block_index = 0; block_index < full_blocks; ++block_index) {
            const auto current_block = bytes_to_u32x4_block(input_bytes.data() + block_index * block_size);
            const auto encrypted_block = ENCRYPT_BLOCK(bytes_to_u32x4_block(xor_blocks(
                u32x4_block_to_bytes(current_block),
                previous_block
            ).data()));
            const auto encrypted_bytes = u32x4_block_to_bytes(encrypted_block);
            std::copy(encrypted_bytes.begin(), encrypted_bytes.end(), output_bytes.begin() + block_index * block_size);
            previous_block = encrypted_bytes;
        }

        return output_bytes;
    }

    for (std::size_t block_index = 0; block_index + 1 < full_blocks; ++block_index) {
        const auto current_block = bytes_to_u32x4_block(input_bytes.data() + block_index * block_size);
        const auto encrypted_block = ENCRYPT_BLOCK(bytes_to_u32x4_block(xor_blocks(
            u32x4_block_to_bytes(current_block),
            previous_block
        ).data()));
        const auto encrypted_bytes = u32x4_block_to_bytes(encrypted_block);
        std::copy(encrypted_bytes.begin(), encrypted_bytes.end(), output_bytes.begin() + block_index * block_size);
        previous_block = encrypted_bytes;
    }

    const std::size_t penultimate_offset = (full_blocks - 1) * block_size;
    const auto penultimate_block = bytes_to_u32x4_block(input_bytes.data() + penultimate_offset);
    const auto chained_penultimate = u32x4_block_to_bytes(ENCRYPT_BLOCK(bytes_to_u32x4_block(xor_blocks(
        u32x4_block_to_bytes(penultimate_block),
        previous_block
    ).data())));

    std::array<uint8_t, block_size> last_input_block{};
    for (std::size_t index = 0; index < tail_size; ++index) {
        last_input_block[index] = input_bytes[penultimate_offset + block_size + index] ^ chained_penultimate[index];
    }
    for (std::size_t index = tail_size; index < block_size; ++index) {
        last_input_block[index] = chained_penultimate[index];
    }

    const auto encrypted_last_block = u32x4_block_to_bytes(ENCRYPT_BLOCK(bytes_to_u32x4_block(last_input_block.data())));
    std::copy(encrypted_last_block.begin(), encrypted_last_block.end(), output_bytes.begin() + penultimate_offset);
    std::copy(chained_penultimate.begin(), chained_penultimate.begin() + tail_size,
              output_bytes.begin() + penultimate_offset + block_size);

    return output_bytes;
}

std::vector<uint8_t> BelT::DECRYPTION_CBC(std::span<const uint8_t> input_bytes, std::span<const uint8_t, 16> S) {
    if (input_bytes.size() < block_size) {
        throw std::invalid_argument("Incorrect text size");
    }

    std::vector<uint8_t> output_bytes(input_bytes.size());
    const std::size_t full_blocks = input_bytes.size() / block_size;
    const std::size_t tail_size = input_bytes.size() % block_size;

    std::array<uint8_t, block_size> previous_cipher_block{};
    std::copy(S.begin(), S.end(), previous_cipher_block.begin());

    if (tail_size == 0) {
        for (std::size_t block_index = 0; block_index < full_blocks; ++block_index) {
            const auto cipher_block = bytes_to_u32x4_block(input_bytes.data() + block_index * block_size);
            const auto decrypted_block = u32x4_block_to_bytes(DECRYPT_BLOCK(cipher_block));
            const auto plain_block = xor_blocks(decrypted_block, previous_cipher_block);
            std::copy(plain_block.begin(), plain_block.end(), output_bytes.begin() + block_index * block_size);
            std::copy(input_bytes.begin() + block_index * block_size,
                      input_bytes.begin() + (block_index + 1) * block_size,
                      previous_cipher_block.begin());
        }

        return output_bytes;
    }

    for (std::size_t block_index = 0; block_index + 1 < full_blocks; ++block_index) {
        const auto cipher_block = bytes_to_u32x4_block(input_bytes.data() + block_index * block_size);
        const auto decrypted_block = u32x4_block_to_bytes(DECRYPT_BLOCK(cipher_block));
        const auto plain_block = xor_blocks(decrypted_block, previous_cipher_block);
        std::copy(plain_block.begin(), plain_block.end(), output_bytes.begin() + block_index * block_size);
        std::copy(input_bytes.begin() + block_index * block_size,
                  input_bytes.begin() + (block_index + 1) * block_size,
                  previous_cipher_block.begin());
    }

    const std::size_t penultimate_offset = (full_blocks - 1) * block_size;
    const std::size_t tail_offset = penultimate_offset + block_size;

    const auto decrypted_penultimate = u32x4_block_to_bytes(DECRYPT_BLOCK(
        bytes_to_u32x4_block(input_bytes.data() + penultimate_offset)
    ));

    std::array<uint8_t, block_size> tail_block{};
    std::copy(input_bytes.begin() + tail_offset, input_bytes.end(), tail_block.begin());

    auto tail_and_r = xor_blocks(decrypted_penultimate, tail_block);

    std::array<uint8_t, block_size> reconstructed_tail_block{};
    std::copy(tail_block.begin(), tail_block.begin() + tail_size, reconstructed_tail_block.begin());
    std::copy(tail_and_r.begin() + tail_size, tail_and_r.end(), reconstructed_tail_block.begin() + tail_size);

    const auto decrypted_tail_block = u32x4_block_to_bytes(DECRYPT_BLOCK(
        bytes_to_u32x4_block(reconstructed_tail_block.data())
    ));
    const auto penultimate_plain = xor_blocks(decrypted_tail_block, previous_cipher_block);

    std::copy(penultimate_plain.begin(), penultimate_plain.end(), output_bytes.begin() + penultimate_offset);
    std::copy(tail_and_r.begin(), tail_and_r.begin() + tail_size, output_bytes.begin() + tail_offset);

    return output_bytes;
}
