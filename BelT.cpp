#include "BelT.h"

BelT::BelT(const std::string& key_str, CipherMode mode){
    // Check size of key > 256 bit
    if (key_str.size() > 32) {
        throw std::invalid_argument("Incorrect key size");
    }

    std::vector<uint32_t> KEY = KeyToNum(key_str);
    KeyExpansion(KEY);

    SetRoundKeys(KEY);
    this->mode = mode;
}

std::vector<uint32_t> BelT::KeyToNum(const std::string& key_str) {
    if (key_str.size() != 16 && key_str.size() != 24 && key_str.size() != 32) {
        throw std::invalid_argument("Incorrect key size");
    }
    std::vector<uint32_t> KEY(key_str.size() / 4);
    KEY.reserve(8);

    for (uint8_t i = 0; i < KEY.size(); ++i) {
        KEY[i] = WordToNumToWord(StrToUint(key_str, i));
    }
    return KEY;
    
}
void BelT::KeyExpansion(std::vector<uint32_t>& KEY) {
    if (KEY.size() == 8) {
    }
    else if (KEY.size() == 6) {
        KEY.push_back(KEY[0] ^ KEY[1] ^ KEY[2]);
        KEY.push_back(KEY[3] ^ KEY[4] ^ KEY[5]);
    }
    else if (KEY.size() == 4) {
        KEY.push_back(KEY[0]);
        KEY.push_back(KEY[1]);
        KEY.push_back(KEY[2]);
        KEY.push_back(KEY[3]);
    }
}
void BelT::SetRoundKeys(const std::vector<uint32_t>& KEY) {
    for (uint8_t i = 0; i < 56; ++i) {
        this->ROUND_KEY[i] = KEY[i % 8];
    }
}
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
std::string BelT::encrypt(const std::string& plaintext, const std::string& iv, std::string* auth_tag) {
    switch (mode) {
    case CipherMode::ECB: return ENCRYPTION_ECB(plaintext);
    case CipherMode::CTR: if (iv.empty()) throw std::invalid_argument("CTR mode requires IV"); return ENCRYPTION_CTR(plaintext, iv);
    //case CipherMode::MAC: return ENCRYPTION_MAC(plaintext);
    case CipherMode::GCM: {
        if (iv.empty()) throw std::invalid_argument("GCM mode requires IV");
        GCM_Result result = ENCRYPTION_GCM(plaintext, iv);
        //if (auth_tag) *auth_tag = result.tag;
        return result.ciphertext;
    }
    default:  throw std::runtime_error("Unsupported cipher mode");  
    }
}
std::string BelT::decrypt(const std::string& plaintext, const std::string& iv, const std::string& auth_tag) {
    switch (mode) {
    case CipherMode::ECB: return DECRYPTION_ECB(plaintext);
    case CipherMode::CTR: { 
        if (iv.empty()) throw std::invalid_argument("CTR mode requires IV");
        return DECRYPTION_CTR(plaintext, iv); 
    }
    case CipherMode::GCM: {
        if (iv.empty()) throw std::invalid_argument("GCM mode requires IV");
        GCM_Result result = ENCRYPTION_GCM(plaintext, iv);
        //if (auth_tag) *auth_tag = result.tag;
        return result.ciphertext;
    }
    default:  throw std::runtime_error("Unsupported cipher mode");
    }   
}

BelT::GCM_Result BelT::ENCRYPTION_GCM(const std::string& plaintext, const std::string& nonce) {
    GCM_Result x;
    return x;
}
std::string BelT::phi1(const std::string& r) {
    auto words = Split128To32(r);
    uint32_t temp = words[0] ^ words[1];
    return Connect32To128({ words[1], words[2], words[3], temp });
}

std::string BelT::phi2(const std::string& r) {
    auto words = Split128To32(r);
    uint32_t temp = words[0] ^ words[3];
    return Connect32To128({ temp, words[0], words[1], words[2] });
}

// Дополнение для неполных блоков
std::string BelT::psi(const std::string& u) {
    if (u.size() == 16) return u;
    std::string result = u;
    result += '\x80';
    result.append(15 - u.size(), '\x00');
    return result;
}

// XOR для строк
std::string BelT::xor_strings(const std::string& a, const std::string& b) {
    std::string result;
    for (size_t i = 0; i < a.size() && i < b.size(); ++i) {
        result += a[i] ^ b[i];
    }
    return result;
}

// Реализация belt-mac
std::string BelT::belt_mac(const std::string& data) {
    std::vector<std::string> blocks = SplitTo128(data);

    std::string s(16, '\x00');
    std::string r = ENCRYPT_ONE_BLOCK(s);

    for (size_t i = 0; i < blocks.size() - 1; ++i) {
        s = xor_strings(s, blocks[i]);
        s = ENCRYPT_ONE_BLOCK(s);
    }

    std::string last_block = blocks.back();
    if (last_block.size() == 16) {
        s = xor_strings(s, xor_strings(last_block, phi1(r)));
    }
    else {
        s = xor_strings(s, xor_strings(psi(last_block), phi2(r)));
    }

    std::string tag = ENCRYPT_ONE_BLOCK(s);
    return tag.substr(0, 8); // Первые 64 бита
}
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
std::string BelT::ENCRYPT_ONE_BLOCK(const std::string& X_str) {
    std::vector<uint32_t> X = Split128To32(X_str);

    uint32_t a = WordToNumToWord(X[0]);
    uint32_t b = WordToNumToWord(X[1]);
    uint32_t c = WordToNumToWord(X[2]);
    uint32_t d = WordToNumToWord(X[3]);
    uint32_t e;

    for (uint8_t i = 1; i < 9; ++i) {
        b = b ^ G_func(a + ROUND_KEY[7 * i - 7], 5);
        c = c ^ G_func(d + ROUND_KEY[7 * i - 6], 21);
        a = a - G_func(b + ROUND_KEY[7 * i - 5], 13);
        e = G_func(b + c + ROUND_KEY[7 * i - 4], 21) ^ i;
        b = b + e;
        c = c - e;
        d = d + G_func(c + ROUND_KEY[7 * i - 3], 13);
        b = b ^ G_func(a + ROUND_KEY[7 * i - 2], 21);
        c = c ^ G_func(d + ROUND_KEY[7 * i - 1], 5);
        std::swap(a, b);
        std::swap(c, d);
        std::swap(b, c);
    }
    std::vector<uint32_t> Y(4);
    Y[0] = WordToNumToWord(b);
    Y[1] = WordToNumToWord(d);
    Y[2] = WordToNumToWord(a);
    Y[3] = WordToNumToWord(c);
    std::string Y_str = Connect32To128(Y);
    return Y_str;
}
std::string BelT::ENCRYPTION_ECB(const std::string& text) {
    // Check size of text >= 128 bit
    if (text.size() < 16) {
        throw std::invalid_argument("Incorrect text size");
    }

    std::vector<std::string> blocks_128b = SplitTo128(text);

    uint32_t num_of_blocks = blocks_128b.size();
    uint8_t length_last_block = text.size() % 16;

    std::string text_encrypted;
    for (uint32_t i = 0; i < num_of_blocks; ++i) {
        if (length_last_block != 0 && i == num_of_blocks - 2) {
            std::string enc_last_block = ENCRYPT_ONE_BLOCK(blocks_128b[i]);
            std::string r = enc_last_block.substr(length_last_block, 16 - length_last_block);
            enc_last_block = enc_last_block.substr(0, length_last_block);

            text_encrypted += ENCRYPT_ONE_BLOCK(blocks_128b[i + 1] + r);
            text_encrypted += enc_last_block;
            break;
        }
        text_encrypted += ENCRYPT_ONE_BLOCK(blocks_128b[i]);
    }
    return text_encrypted;
}
std::string BelT::ENCRYPTION_CTR(const std::string& text, const std::string& iv) {
    // Проверка размера IV (синхропосылки)
    if (iv.size() != 16) {
        throw std::invalid_argument("IV must be 16 bytes (128 bits)");
    }

    // Разбиваем текст на блоки по 16 байт
    std::vector<std::string> blocks = SplitTo128(text);
    std::string result;

    // Инициализируем s = belt-block(S, K)
    std::string s = ENCRYPT_ONE_BLOCK(iv);

    for (size_t i = 0; i < blocks.size(); ++i) {
        // 1. s = s + 1 (инкремент 128-битного числа)
        for (int j = 0; j <= 15; ++j) {
            if (++s[j] != 0) break; // Учитываем перенос
        }

        // 2. Шифруем текущее значение s
        std::string encrypted_s = ENCRYPT_ONE_BLOCK(s);

        // 3. Берем нужное количество байт (|X_i|)
        size_t block_size = blocks[i].size();
        std::string keystream = encrypted_s.substr(0, block_size);

        // 4. XOR с исходным блоком
        std::string encrypted_block;
        for (size_t j = 0; j < block_size; ++j) {
            encrypted_block += blocks[i][j] ^ keystream[j];
        }

        result += encrypted_block;
    }

    return result;
}

// Для CTR режима шифрование и дешифрование одинаковы
std::string BelT::DECRYPTION_CTR(const std::string& ciphertext, const std::string& iv) {
    return ENCRYPTION_CTR(ciphertext, iv);
}

std::string BelT::DECRYPT_ONE_BLOCK(const std::string& Y_str) {
    std::vector<uint32_t> Y = Split128To32(Y_str);

    uint32_t a = WordToNumToWord(Y[0]);
    uint32_t b = WordToNumToWord(Y[1]);
    uint32_t c = WordToNumToWord(Y[2]);
    uint32_t d = WordToNumToWord(Y[3]);
    uint32_t e;

    for (uint8_t i = 8; i > 0; --i) {
        b = b ^ G_func(a + ROUND_KEY[7 * i - 1], 5);
        c = c ^ G_func(d + ROUND_KEY[7 * i - 2], 21);
        a = a - G_func(b + ROUND_KEY[7 * i - 3], 13);
        e = G_func(b + c + ROUND_KEY[7 * i - 4], 21) ^ i;
        b = b + e;
        c = c - e;
        d = d + G_func(c + ROUND_KEY[7 * i - 5], 13);
        b = b ^ G_func(a + ROUND_KEY[7 * i - 6], 21);
        c = c ^ G_func(d + ROUND_KEY[7 * i - 7], 5);
        std::swap(a, b);
        std::swap(c, d);
        std::swap(a, d);
    }
    std::vector<uint32_t> X(4);
    X[0] = WordToNumToWord(c);
    X[1] = WordToNumToWord(a);
    X[2] = WordToNumToWord(d);
    X[3] = WordToNumToWord(b);

    std::string X_str = Connect32To128(X);
    return X_str;
}
std::string BelT::DECRYPTION_ECB(const std::string& text_encrypted) {
    // Check size of text_encrypted >= 128 bit
    if (text_encrypted.size() < 16) {
        throw std::invalid_argument("Incorrect ciphertext size");
    }

    std::vector<std::string> blocks_128b = SplitTo128(text_encrypted);

    uint32_t num_blocks = blocks_128b.size();
    uint8_t length_last_block = text_encrypted.size() % 16;

    std::string text;
    for (uint32_t i = 0; i < num_blocks; ++i) {
        if (length_last_block != 0 && i == num_blocks - 2) {
            std::string enc_last_block = DECRYPT_ONE_BLOCK(blocks_128b[i]);
            std::string r = enc_last_block.substr(length_last_block, 16 - length_last_block);
            enc_last_block = enc_last_block.substr(0, length_last_block);

            text += DECRYPT_ONE_BLOCK(blocks_128b[i + 1] + r);
            text += enc_last_block;
            break;
        }
        text += DECRYPT_ONE_BLOCK(blocks_128b[i]);
    }
    return text;
}

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
uint32_t BelT::WordToNumToWord(uint32_t word) {
    uint32_t byte_parts[4]{};
    for (uint8_t i = 0; i < 4; ++i) {
        byte_parts[i] = (word >> (24 - i * 8)) & 0b11111111;
    }
    word = byte_parts[0] + (byte_parts[1] << 8) + (byte_parts[2] << 16) + (byte_parts[3] << 24);
    return word;
}
uint32_t BelT::StrToUint(const std::string& str, uint32_t start_index) {
    uint32_t block_32b = 0;
    for (uint8_t j = 0; j < 4; ++j) {
        block_32b |= static_cast<unsigned char>(str[4 * start_index + j]) << (8 * (3 - j));
    }
    return block_32b;
}

uint32_t BelT::ShLo(uint32_t word) {
    return word >> 1;
}
uint32_t BelT::ShHi(uint32_t word) {
    return word << 1;
}
uint32_t BelT::RotHi(uint32_t word) {
    uint32_t result_sh_lo = word;
    for (int i = 0; i < 31; ++i) {
        result_sh_lo = ShLo(result_sh_lo);
    }
    return ShHi(word) ^ result_sh_lo;
}

uint32_t BelT::G_func(uint32_t word, uint8_t r) {
    std::vector<uint8_t> PARTS_8b = Split32To8(word);

    for (int i = 0; i < 4; ++i) {
        PARTS_8b[i] = H_func(PARTS_8b[i]);
    }

    uint32_t result = Connect8To32(PARTS_8b);

    for (int i = 0; i < r; ++i) {
        result = RotHi(result);
    }

    return result;
}
uint32_t BelT::H_func(uint8_t word) {
    uint32_t H_box[16][16] = {
    {0xB1, 0x94, 0xBA, 0xC8, 0x0A, 0x08, 0xF5, 0x3B, 0x36, 0x6D, 0x00, 0x8E, 0x58, 0x4A, 0x5D, 0xE4},
    {0x85, 0x04, 0xFA, 0x9D, 0x1B, 0xB6, 0xC7, 0xAC, 0x25, 0x2E, 0x72, 0xC2, 0x02, 0xFD, 0xCE, 0x0D},
    {0x5B, 0xE3, 0xD6, 0x12, 0x17, 0xB9, 0x61, 0x81, 0xFE, 0x67, 0x86, 0xAD, 0x71, 0x6B, 0x89, 0x0B},
    {0x5C, 0xB0, 0xC0, 0xFF, 0x33, 0xC3, 0x56, 0xB8, 0x35, 0xC4, 0x05, 0xAE, 0xD8, 0xE0, 0x7F, 0x99},
    {0xE1, 0x2B, 0xDC, 0x1A, 0xE2, 0x82, 0x57, 0xEC, 0x70, 0x3F, 0xCC, 0xF0, 0x95, 0xEE, 0x8D, 0xF1},
    {0xC1, 0xAB, 0x76, 0x38, 0x9F, 0xE6, 0x78, 0xCA, 0xF7, 0xC6, 0xF8, 0x60, 0xD5, 0xBB, 0x9C, 0x4F},
    {0xF3, 0x3C, 0x65, 0x7B, 0x63, 0x7C, 0x30, 0x6A, 0xDD, 0x4E, 0xA7, 0x79, 0x9E, 0xB2, 0x3D, 0x31},
    {0x3E, 0x98, 0xB5, 0x6E, 0x27, 0xD3, 0xBC, 0xCF, 0x59, 0x1E, 0x18, 0x1F, 0x4C, 0x5A, 0xB7, 0x93},
    {0xE9, 0xDE, 0xE7, 0x2C, 0x8F, 0x0C, 0x0F, 0xA6, 0x2D, 0xDB, 0x49, 0xF4, 0x6F, 0x73, 0x96, 0x47},
    {0x06, 0x07, 0x53, 0x16, 0xED, 0x24, 0x7A, 0x37, 0x39, 0xCB, 0xA3, 0x83, 0x03, 0xA9, 0x8B, 0xF6},
    {0x92, 0xBD, 0x9B, 0x1C, 0xE5, 0xD1, 0x41, 0x01, 0x54, 0x45, 0xFB, 0xC9, 0x5E, 0x4D, 0x0E, 0xF2},
    {0x68, 0x20, 0x80, 0xAA, 0x22, 0x7D, 0x64, 0x2F, 0x26, 0x87, 0xF9, 0x34, 0x90, 0x40, 0x55, 0x11},
    {0xBE, 0x32, 0x97, 0x13, 0x43, 0xFC, 0x9A, 0x48, 0xA0, 0x2A, 0x88, 0x5F, 0x19, 0x4B, 0x09, 0xA1},
    {0x7E, 0xCD, 0xA4, 0xD0, 0x15, 0x44, 0xAF, 0x8C, 0xA5, 0x84, 0x50, 0xBF, 0x66, 0xD2, 0xE8, 0x8A},
    {0xA2, 0xD7, 0x46, 0x52, 0x42, 0xA8, 0xDF, 0xB3, 0x69, 0x74, 0xC5, 0x51, 0xEB, 0x23, 0x29, 0x21},
    {0xD4, 0xEF, 0xD9, 0xB4, 0x3A, 0x62, 0x28, 0x75, 0x91, 0x14, 0x10, 0xEA, 0x77, 0x6C, 0xDA, 0x1D}
    };
    return H_box[word / 16][word % 16];
}

std::vector<std::string> BelT::SplitTo128(const std::string& text) {
    uint32_t num_blocks = (text.size() + 15) / 16; // the number of blocks rounded up
    std::vector<std::string> blocks_128b(num_blocks);

    for (uint32_t i = 0; i < num_blocks; ++i) {
        uint32_t start_part = 16 * i;
        uint8_t size_block = std::min(16, static_cast<int>(text.size() - (start_part)));
        blocks_128b[i] = text.substr(start_part, size_block);
    }
    return blocks_128b;
}
std::vector<uint32_t> BelT::Split128To32(const std::string& block_128b) {
    std::vector<uint32_t> blocks_32b(4);
    for (uint8_t i = 0; i < 4; ++i) {
        blocks_32b[i] = StrToUint(block_128b, i);
    }
    return blocks_32b;
}
std::vector<uint8_t> BelT::Split32To8(uint32_t block_32b) {
    std::vector<uint8_t> blocks_8b(4);
    for (uint8_t i = 0; i < 4; ++i) {
        blocks_8b[i] = (block_32b >> (32 - (i + 1) * 8)) & 0xFF;
    }
    return blocks_8b;
}

uint32_t BelT::Connect8To32(const std::vector<uint8_t>& blocks_8b) {
    uint32_t block_32b = 0;
    for (uint32_t i = 0; i < 4; ++i) {
        block_32b |= blocks_8b[i] << (32 - (i + 1) * 8);
    }
    return block_32b;
}
std::string  BelT::Connect32To128(const std::vector<uint32_t>& blocks_32b) {
    std::string block_128b;
    for (uint8_t i = 0; i < 4; ++i) {
        for (int8_t j = 3; j >= 0; --j) {
            block_128b += static_cast<char>((blocks_32b[i] >> (8 * j)) & 0xFF);
        }
    }
    return block_128b;
}