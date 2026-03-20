#include "BelT.h"

const uint8_t BLOCK_128_length = 16;
const uint8_t KEY_128_length = 16;
const uint8_t KEY_192_length = 24;
const uint8_t KEY_256_length = 32;
const uint8_t IV_128_length = 16;

BelT::BelT(const std::string& key_str, CipherMode mode){
    // Check size of key > 256 bit
    if (key_str.size() > KEY_256_length) {
        throw std::invalid_argument("Incorrect key size");
    }

    std::vector<uint32_t> KEY = KeyToNum(key_str);
    KeyExpansion(KEY);

    SetRoundKeys(KEY);
    this->mode = mode;
}

std::string BelT::encrypt(const std::string& plaintext, const std::string& iv) {
    switch (mode) {
    case CipherMode::ECB: {
        return ENCRYPTION_ECB(plaintext);
    }
    case CipherMode::CTR: {
        if (iv.empty()) throw std::invalid_argument("CTR mode requires IV");
        return ENCRYPTION_CTR(plaintext, iv);
    }
    case CipherMode::MAC: {
        return ENCRYPTION_MAC(plaintext);
    }
    default:  throw std::runtime_error("Unsupported cipher mode");  
    }
}

std::string BelT::decrypt(const std::string& ciphertext, const std::string& iv) {
    switch (mode) {
    case CipherMode::ECB: {
        return DECRYPTION_ECB(ciphertext);
    }
    case CipherMode::CTR: { 
        if (iv.empty()) throw std::invalid_argument("CTR mode requires IV");
        return DECRYPTION_CTR(ciphertext, iv);
    }
    default:  throw std::runtime_error("Unsupported cipher mode");
    }   
}


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