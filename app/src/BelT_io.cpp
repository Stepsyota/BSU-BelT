#include "BelT.h"

void BelT::encrypt_file(const std::string& input_filename, const std::string& output_filename, const std::string& iv) {
    std::string plaintext = read_file(input_filename);
    std::string ciphertext = encrypt(plaintext, iv);
    write_to_file(output_filename, ciphertext);
}

void BelT::decrypt_file(const std::string& input_filename, const std::string& output_filename, const std::string& iv) {
    std::string ciphertext = read_file(input_filename);
    std::string plaintext = decrypt(ciphertext, iv);
    write_to_file(output_filename, plaintext);
}

std::string BelT::read_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) throw std::runtime_error("Не удалось открыть файл для чтения: " + filename);

    std::ostringstream ss;
    ss << file.rdbuf();
    return ss.str();
}
void BelT::write_to_file(const std::string& filename, const std::string& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) throw std::runtime_error("Не удалось открыть файл для записи: " + filename);

    file.write(data.c_str(), data.size());
}