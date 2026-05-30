#include "../include/BelT.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>


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

std::vector<uint8_t> BelT::ENCRYPTION_ECB(std::span<const uint8_t> input_bytes) {
    std::vector<uint8_t> output_bytes(input_bytes.size());

    const size_t len_last_block = input_bytes.size() % BLOCK_128_length;
    const size_t offset_last_block = (input_bytes.size() - len_last_block);

    if (len_last_block == 0) {
        for (uint8_t off = 0; off < input_bytes.size(); off += BLOCK_128_length) {
            auto word = bytes_to_u32x4_block(input_bytes.data() + off);

            auto encrypted_word = ENCRYPT_BLOCK(word);

            auto encrypted_bytes = u32x4_block_to_bytes(encrypted_word);
            std::copy(encrypted_bytes.begin(), encrypted_bytes.end(),output_bytes.begin() + off);
        }

        return output_bytes;
    }

    const size_t tail_offset  = input_bytes.size() - len_last_block;
    const size_t penultimate_offset  = tail_offset - BLOCK_128_length;
    
    for (size_t off = 0; off < penultimate_offset; off += BLOCK_128_length) {
        auto block = bytes_to_u32x4_block(input_bytes.data() + off);

        auto encrypted_block = ENCRYPT_BLOCK(block);

        auto encrypted_bytes = u32x4_block_to_bytes(encrypted_block);
        std::copy(encrypted_bytes.begin(), encrypted_bytes.end(),output_bytes.begin() + off);
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
    std::copy(enc_last_bytes.begin(), enc_last_bytes.end(),output_bytes.begin() + penultimate_offset);

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
            std::copy(encrypted_bytes.begin(), encrypted_bytes.end(),output_bytes.begin() + off);
        }

        return output_bytes;
    }

    const size_t tail_offset  = input_bytes.size() - len_last_block;
    const size_t penultimate_offset  = tail_offset - BLOCK_128_length;
    
    for (size_t off = 0; off < penultimate_offset; off += BLOCK_128_length) {
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
    for (size_t i = len_last_block; i < BLOCK_128_length; ++i) {
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


std::vector<uint8_t> BelT::ENCRYPTION_CTR(std::span<const uint8_t> plaintext,std::span<const uint8_t, 16> iv) {

    if (plaintext.size() < BLOCK_128_length) {
        throw std::invalid_argument("Incorrect text size");
    }

    std::vector<uint8_t> ciphertext;
    ciphertext.resize(plaintext.size());

    std::array<uint8_t, 16> s = u32x4_block_to_bytes(ENCRYPT_BLOCK(bytes_to_u32x4_block(iv.data())));

    const std::size_t blocks_count = (plaintext.size() + 15) / 16;

    for (std::size_t block_index = 0; block_index < blocks_count; ++block_index) {
        for (std::size_t byte_index = 0; byte_index < 16; ++byte_index) {
            if (++s[byte_index] != 0) {
                break;
            }
        }

        auto encrypted_s = u32x4_block_to_bytes(ENCRYPT_BLOCK(bytes_to_u32x4_block(s.data())));

        const std::size_t offset = block_index * 16;
        const std::size_t block_size = std::min<std::size_t>(16, plaintext.size() - offset);

        for (std::size_t i = 0; i < block_size; ++i) {
            ciphertext[offset + i] = plaintext[offset + i] ^ encrypted_s[i];
        }
    }

    return ciphertext;
}

std::vector<uint8_t> BelT::DECRYPTION_CTR(std::span<const uint8_t> data,std::span<const uint8_t, 16> IV) {
    return ENCRYPTION_CTR(data, IV);
}

std::vector<uint8_t> BelT::ENCRYPTION_MAC(std::span<const uint8_t> data) {
    std::array<uint8_t, BLOCK_128_length> state{};
    std::array<uint8_t, BLOCK_128_length> zero_block{};
    const auto round_key_block = u32x4_block_to_bytes(ENCRYPT_BLOCK(bytes_to_u32x4_block(zero_block.data())));

    const std::size_t full_blocks = data.size() / BLOCK_128_length;
    const std::size_t tail_size = data.size() % BLOCK_128_length;
    const std::size_t blocks_to_mix = data.empty() ? 0 : (tail_size == 0 ? full_blocks - 1 : full_blocks);

    for (std::size_t block_index = 0; block_index < blocks_to_mix; ++block_index) {
        std::array<uint8_t, BLOCK_128_length> block{};
        std::copy_n(data.begin() + block_index * BLOCK_128_length, BLOCK_128_length, block.begin());
        state = u32x4_block_to_bytes(ENCRYPT_BLOCK(bytes_to_u32x4_block(xor_blocks(state, block).data())));
    }

    std::array<uint8_t, BLOCK_128_length> last_block{};
    if (!data.empty()) {
        const std::size_t tail_offset = blocks_to_mix * BLOCK_128_length;
        const std::size_t last_size = data.size() - tail_offset;
        std::copy_n(data.begin() + tail_offset, last_size, last_block.begin());

        if (last_size == BLOCK_128_length) {
            last_block = xor_blocks(last_block, phi1(round_key_block));
        } else {
            last_block = xor_blocks(pad_mac_block(data.subspan(tail_offset, last_size)), phi2(round_key_block));
        }
    } else {
        last_block = xor_blocks(pad_mac_block(data), phi2(round_key_block));
    }

    state = xor_blocks(state, last_block);
    auto tag_block = u32x4_block_to_bytes(ENCRYPT_BLOCK(bytes_to_u32x4_block(state.data())));

    return std::vector<uint8_t>(tag_block.begin(), tag_block.begin() + 8);
}
