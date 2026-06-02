#include "../include/BelT.h"
#include <array>
#include <bit>
#include <cstdint>
#include <stdexcept>

BelT::BelT(const std::array<uint8_t, KEY_128_length>& key) {
    SetRoundKeys(key.data(), KEY_128_length);
}

BelT::BelT(const std::array<uint8_t, KEY_192_length>& key) {
    SetRoundKeys(key.data(), KEY_192_length);
}

BelT::BelT(const std::array<uint8_t, KEY_256_length>& key) {
    SetRoundKeys(key.data(), KEY_256_length);
}


std::array<uint32_t, 4> BelT::ENCRYPT_BLOCK(std::array<uint32_t, 4> X) {
    uint32_t a = std::byteswap(X[0]);
    uint32_t b = std::byteswap(X[1]);
    uint32_t c = std::byteswap(X[2]);
    uint32_t d = std::byteswap(X[3]);
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

    std::array<uint32_t, 4> X = {
        std::byteswap(c), std::byteswap(a), 
        std::byteswap(d), std::byteswap(b)
    };
    return X;
}



std::vector<uint8_t> BelT::encrypt(
    std::span<const uint8_t> data,
    CipherMode mode,
    std::optional<std::span<const uint8_t, 16>> IV,
    std::optional<std::span<const uint8_t>> aad
) {
    switch (mode) {
        case CipherMode::ECB: {
            return BelT::encrypt_ecb(data);
        }
        case CipherMode::CTR: {
            if (!IV.has_value()) {
                throw std::runtime_error("CTR mode requires IV");  
            }
            return BelT::encrypt_ctr(data, IV.value());
        }
        case CipherMode::CBC: {
            if (!IV.has_value()) {
                throw std::runtime_error("CBC mode requires IV");  
            }
            return BelT::encrypt_cbc(data, IV.value());
        }
        case CipherMode::MAC: {
            return BelT::encrypt_mac(data);
        }
        case CipherMode::CCM: {
            if (!IV.has_value()) {
                throw std::runtime_error("CCM mode requires IV");
            }
            return BelT::encrypt_ccm(data, IV.value());
        }
        case CipherMode::GCM: {
            if (!IV.has_value()) {
                throw std::runtime_error("GCM mode requires IV");
            }
            const std::span<const uint8_t> aad_span = aad.value_or(std::span<const uint8_t>{});
            return BelT::encrypt_gcm(data, std::span<const uint8_t>(IV->data(), IV->size()), aad_span);
        }
        default:  throw std::runtime_error("Unsupported cipher mode");  
    }

}

std::vector<uint8_t> BelT::encrypt_ecb(std::span<const uint8_t> data) {
    return ENCRYPTION_ECB(data);
}

std::vector<uint8_t> BelT::encrypt_cbc(std::span<const uint8_t> data, std::span<const uint8_t, 16> IV) {
    return ENCRYPTION_CBC(data, IV);
}

std::vector<uint8_t> BelT::encrypt_ctr(std::span<const uint8_t> data, std::span<const uint8_t, 16> IV) {
    return ENCRYPTION_CTR(data, IV);
}

std::vector<uint8_t> BelT::encrypt_mac(std::span<const uint8_t> data) {
    return ENCRYPTION_MAC(data);
}

std::vector<uint8_t> BelT::encrypt_ccm(std::span<const uint8_t> data, std::span<const uint8_t, 16> IV) {
    return ENCRYPTION_CCM(data, IV);
}

std::vector<uint8_t> BelT::encrypt_gcm(std::span<const uint8_t> data, std::span<const uint8_t> nonce, std::optional<std::span<const uint8_t>> aad) {
    return gcm_encrypt(data, nonce, aad);
}


std::vector<uint8_t> BelT::decrypt(
    std::span<const uint8_t> data,
    CipherMode mode,
    std::optional<std::span<const uint8_t, 16>> IV,
    std::optional<std::span<const uint8_t>> aad
) {
        switch (mode) {
        case CipherMode::ECB: {
            return BelT::decrypt_ecb(data);
        }
        case CipherMode::CTR: {
            if (!IV.has_value()) {
                throw std::runtime_error("CTR mode requires IV");  
            }
            return BelT::decrypt_ctr(data, IV.value());
        }
        case CipherMode::CBC: {
            if (!IV.has_value()) {
                throw std::runtime_error("CBC mode requires IV");  
            }
            return BelT::decrypt_cbc(data, IV.value());
        }
        case CipherMode::CCM: {
            if (!IV.has_value()) {
                throw std::runtime_error("CCM mode requires IV");
            }
            return BelT::decrypt_ccm(data, IV.value());
        }
        case CipherMode::GCM: {
            if (!IV.has_value()) {
                throw std::runtime_error("GCM mode requires IV");
            }
            const std::span<const uint8_t> aad_span = aad.value_or(std::span<const uint8_t>{});
            return BelT::decrypt_gcm(data, std::span<const uint8_t>(IV->data(), IV->size()), aad_span);
        }
        default:  throw std::runtime_error("Unsupported cipher mode"); 
    }
}

std::vector<uint8_t> BelT::decrypt_ecb(std::span<const uint8_t> data) {
    return DECRYPTION_ECB(data);
}

std::vector<uint8_t> BelT::decrypt_cbc(std::span<const uint8_t> data, std::span<const uint8_t, 16> IV) {
    return DECRYPTION_CBC(data, IV);
}

std::vector<uint8_t> BelT::decrypt_ctr(std::span<const uint8_t> data, std::span<const uint8_t, 16> IV) {
    return DECRYPTION_CTR(data, IV);
}

std::vector<uint8_t> BelT::decrypt_ccm(std::span<const uint8_t> data, std::span<const uint8_t, 16> IV) {
    return DECRYPTION_CCM(data, IV);
}

std::vector<uint8_t> BelT::decrypt_gcm(std::span<const uint8_t> data, std::span<const uint8_t> nonce, std::optional<std::span<const uint8_t>> aad) {
    return gcm_decrypt(data, nonce, aad);
}
