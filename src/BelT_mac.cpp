#include "../include/BelT.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

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
