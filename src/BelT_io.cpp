#include "../include/BelT.h"

#include <fstream>
#include <iterator>
#include <stdexcept>

std::vector<uint8_t> BelT::read_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file for reading: " + filename);
    }

    return std::vector<uint8_t>(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
}

void BelT::write_to_file(const std::string& filename, std::span<const uint8_t> data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file for writing: " + filename);
    }

    file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

void BelT::encrypt_file(
    const std::string& input_filename,
    const std::string& output_filename,
    CipherMode mode,
    std::optional<std::span<const uint8_t, 16>> IV
) {
    auto input = read_file(input_filename);
    auto output = encrypt(input, mode, IV);
    write_to_file(output_filename, output);
}

void BelT::decrypt_file(
    const std::string& input_filename,
    const std::string& output_filename,
    CipherMode mode,
    std::optional<std::span<const uint8_t, 16>> IV
) {
    auto input = read_file(input_filename);
    auto output = decrypt(input, mode, IV);
    write_to_file(output_filename, output);
}
