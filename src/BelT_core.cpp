#include "../include/BelT.h"
#include <array>
#include <bit>
#include <cstdint>
#include <expected>

BelT::BelT(){
    
}

std::expected<BelT, BelTError> BelT::create(const std::array<uint8_t, KEY_128_length>& key) {
    BelT cipher;
    cipher.SetRoundKeys(key.data(), KEY_128_length);
    return cipher;
}

std::expected<BelT, BelTError> BelT::create(const std::array<uint8_t, KEY_192_length>& key) {
    BelT cipher;
    cipher.SetRoundKeys(key.data(), KEY_192_length);
    return cipher;
}

std::expected<BelT, BelTError> BelT::create(const std::array<uint8_t, KEY_256_length>& key) {
    BelT cipher;
    cipher.SetRoundKeys(key.data(), KEY_256_length);
    return cipher;
}

std::array<uint32_t, 4> BelT::ENCRYPT_BLOCK(std::array<uint32_t, 4> X) {
    uint32_t a = std::byteswap(X[0]);
    uint32_t b = std::byteswap(X[1]);
    uint32_t c = std::byteswap(X[2]);
    uint32_t d = std::byteswap(X[3]);
    uint32_t e;

    for (uint8_t i = 1; i < 9; ++i) {
        b = b ^ G_funcNEW(a + ROUND_KEY[7 * i - 7], 5);
        c = c ^ G_funcNEW(d + ROUND_KEY[7 * i - 6], 21);
        a = a - G_funcNEW(b + ROUND_KEY[7 * i - 5], 13);
        e = G_funcNEW(b + c + ROUND_KEY[7 * i - 4], 21) ^ i;
        b = b + e;
        c = c - e;
        d = d + G_funcNEW(c + ROUND_KEY[7 * i - 3], 13);
        b = b ^ G_funcNEW(a + ROUND_KEY[7 * i - 2], 21);
        c = c ^ G_funcNEW(d + ROUND_KEY[7 * i - 1], 5);
        std::swap(a, b);
        std::swap(c, d);
        std::swap(b, c);
    }

    std::array<uint32_t, 4> Y = {
        std::byteswap(b), std::byteswap(d),
        std::byteswap(a), std::byteswap(c)
    };
    return Y;
}

std::array<uint32_t, 4> BelT::DECRYPT_BLOCK(std::array<uint32_t, 4> Y) {
    uint32_t a = std::byteswap(Y[0]);
    uint32_t b = std::byteswap(Y[1]);
    uint32_t c = std::byteswap(Y[2]);
    uint32_t d = std::byteswap(Y[3]);
    uint32_t e;

    for (uint8_t i = 8; i > 0; --i) {
        b = b ^ G_funcNEW(a + ROUND_KEY[7 * i - 1], 5);
        c = c ^ G_funcNEW(d + ROUND_KEY[7 * i - 2], 21);
        a = a - G_funcNEW(b + ROUND_KEY[7 * i - 3], 13);
        e = G_funcNEW(b + c + ROUND_KEY[7 * i - 4], 21) ^ i;
        b = b + e;
        c = c - e;
        d = d + G_funcNEW(c + ROUND_KEY[7 * i - 5], 13);
        b = b ^ G_funcNEW(a + ROUND_KEY[7 * i - 6], 21);
        c = c ^ G_funcNEW(d + ROUND_KEY[7 * i - 7], 5);
        std::swap(a, b);
        std::swap(c, d);
        std::swap(a, d);
    }

    std::array<uint32_t, 4> X = {
        std::byteswap(c), std::byteswap(a), 
        std::byteswap(d), std::byteswap(b)
    };
    return X;
}



std::span<const uint8_t> BelT::encryptNEW(std::span<const uint8_t> data, CipherMode mode, std::optional<std::span<const uint8_t, 16>> IV) {
    switch (mode) {
        case CipherMode::ECB: {
            return BelT::ENCRYPTION_ECBNEW(data);
        }
        case CipherMode::CTR: {
            if (!IV.has_value()) {
                throw std::runtime_error("CTR mode requires IV");  
            }
            return BelT::ENCRYPTION_CTRNEW(data, IV.value());
        }
        case CipherMode::MAC: {
            return BelT::ENCRYPTION_MACNEW(data);
        }
        default:  throw std::runtime_error("Unsupported cipher mode");  
    }

}
std::span<const uint8_t> BelT::decryptNEW(std::span<const uint8_t> data, CipherMode mode, std::optional<std::span<const uint8_t, 16>> IV) {
    
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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