#pragma once
#include <iostream>
#include <cstdint>
#include <bitset>
#include <optional>
#include <span>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>

#include <array>

// Cipher operating modes
enum class CipherMode {
	ECB,    // Electronic Codebook
	CBC, 
	CTR,    // Counter mode
	MAC,    // Message authentication code
	CCM,    // Counter with CBC-MAC
};

const uint8_t BLOCK_128_length = 16;
const uint8_t KEY_128_length = 16;
const uint8_t KEY_192_length = 24;
const uint8_t KEY_256_length = 32;
const uint8_t IV_128_length = 16;

class BelT {
public:
	BelT(const std::array<uint8_t, KEY_128_length>& key);
	BelT(const std::array<uint8_t, KEY_192_length>& key);
	BelT(const std::array<uint8_t, KEY_256_length>& key);

	std::vector<uint8_t> encrypt(std::span<const uint8_t> data, CipherMode mode, std::optional<std::span<const uint8_t, 16>> IV = std::nullopt);
	std::vector<uint8_t> decrypt(std::span<const uint8_t> data, CipherMode mode, std::optional<std::span<const uint8_t, 16>> IV = std::nullopt);

	std::vector<uint8_t> encrypt_ecb(std::span<const uint8_t> data);
	std::vector<uint8_t> encrypt_cbc(std::span<const uint8_t> data, std::span<const uint8_t, IV_128_length> IV);
	std::vector<uint8_t> encrypt_ctr(std::span<const uint8_t> data, std::span<const uint8_t, IV_128_length> IV);
	std::vector<uint8_t> encrypt_mac(std::span<const uint8_t> data);
	std::vector<uint8_t> encrypt_ccm(std::span<const uint8_t> data, std::span<const uint8_t, IV_128_length> IV);

	std::vector<uint8_t> decrypt_ecb(std::span<const uint8_t> data);
	std::vector<uint8_t> decrypt_cbc(std::span<const uint8_t> data, std::span<const uint8_t, IV_128_length> IV);
	std::vector<uint8_t> decrypt_ctr(std::span<const uint8_t> data, std::span<const uint8_t, IV_128_length> IV);
	std::vector<uint8_t> decrypt_ccm(std::span<const uint8_t> data, std::span<const uint8_t, IV_128_length> IV);

	void encrypt_file(const std::string& input_filename, const std::string& output_filename, CipherMode mode, std::optional<std::span<const uint8_t, 16>> IV = std::nullopt);
	void decrypt_file(const std::string& input_filename, const std::string& output_filename, CipherMode mode, std::optional<std::span<const uint8_t, 16>> IV = std::nullopt);
private:
	void SetRoundKeys(const uint8_t* data, size_t size);

	std::array<uint32_t, 4> ENCRYPT_BLOCK(std::array<uint32_t, 4> X);
	std::array<uint32_t, 4> DECRYPT_BLOCK(std::array<uint32_t, 4> Y);

	std::vector<uint8_t> ENCRYPTION_ECB(std::span<const uint8_t> data);
	std::vector<uint8_t> ENCRYPTION_CBC(std::span<const uint8_t> data, std::span<const uint8_t, IV_128_length> IV);
	std::vector<uint8_t> ENCRYPTION_CTR(std::span<const uint8_t> data, std::span<const uint8_t, IV_128_length> IV);
	std::vector<uint8_t> ENCRYPTION_MAC(std::span<const uint8_t> data);
	std::vector<uint8_t> ENCRYPTION_CCM(std::span<const uint8_t> data, std::span<const uint8_t, IV_128_length> IV);

	std::vector<uint8_t> DECRYPTION_ECB(std::span<const uint8_t> data);
	std::vector<uint8_t> DECRYPTION_CBC(std::span<const uint8_t> data, std::span<const uint8_t, IV_128_length> IV);
	std::vector<uint8_t> DECRYPTION_CTR(std::span<const uint8_t> data, std::span<const uint8_t, IV_128_length> IV);
	std::vector<uint8_t> DECRYPTION_CCM(std::span<const uint8_t> data, std::span<const uint8_t, IV_128_length> IV);

	std::vector<uint8_t> CTR_CRYPT(std::span<const uint8_t> data, std::span<const uint8_t, IV_128_length> IV);
	std::vector<uint8_t> ccm_auth(std::span<const uint8_t> data, std::span<const uint8_t, IV_128_length> IV);
	std::vector<uint8_t> ccm_encrypt(std::span<const uint8_t> data, std::span<const uint8_t, IV_128_length> IV);
	std::vector<uint8_t> ccm_decrypt(std::span<const uint8_t> data, std::span<const uint8_t, IV_128_length> IV);


	uint32_t ShLo(uint32_t word, uint8_t r);
	uint32_t ShHi(uint32_t word, uint8_t r); 
	uint32_t RotHi(uint32_t word, uint8_t r);
	uint32_t G_func(uint32_t block, uint8_t r);
	uint8_t H_func(uint8_t word);

	std::array<uint8_t, 4> Split32to8(uint32_t block);
	uint32_t Connect8to32(std::array<uint8_t, 4>block);

	std::array<uint8_t, 4> u32_to_bytes(uint32_t x);
	uint32_t bytes_to_u32(const uint8_t* p);

	std::array<uint8_t, BLOCK_128_length> u32x4_block_to_bytes(const std::array<uint32_t, 4>& block);
	std::array<uint32_t, 4> bytes_to_u32x4_block(const uint8_t* p);


	std::vector<uint8_t> read_file(const std::string& filename);
	void write_to_file(const std::string& filename, std::span<const uint8_t> data);


	std::array<uint8_t, BLOCK_128_length> xor_blocks( const std::array<uint8_t, BLOCK_128_length>& left, const std::array<uint8_t, BLOCK_128_length>& right);
	std::array<uint8_t, BLOCK_128_length> increment_counter(std::array<uint8_t, BLOCK_128_length> value);
	std::array<uint8_t, BLOCK_128_length> pad_mac_block(std::span<const uint8_t> tail);

	std::array<uint8_t, BLOCK_128_length> phi1(const std::array<uint8_t, BLOCK_128_length>& r);
	std::array<uint8_t, BLOCK_128_length> phi2(const std::array<uint8_t, BLOCK_128_length>& r);


	std::array<uint32_t, 56> ROUND_KEY{};
};
