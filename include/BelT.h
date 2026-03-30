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

#include <print>
#include <expected>
#include <array>

// Cipher operating modes
enum class CipherMode {
	ECB,    // Electronic Codebook
	CTR,    // Counter mode 	
	MAC,    // Message authentication code
};

enum class BelTError {
	InvalidKeySize,
};

const uint8_t BLOCK_128_length = 16;
const uint8_t KEY_128_length = 16;
const uint8_t KEY_192_length = 24;
const uint8_t KEY_256_length = 32;
const uint8_t IV_128_length = 16;

class BelT {
public:
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	static std::expected<BelT, BelTError> create(const std::array<uint8_t, 16>& key);
	static std::expected<BelT, BelTError> create(const std::array<uint8_t, 24>& key);
	static std::expected<BelT, BelTError> create(const std::array<uint8_t, 32>& key);

	BelT();
	std::vector<uint8_t> encrypt(std::span<const uint8_t> data, CipherMode mode, std::optional<std::span<const uint8_t, 16>> IV = std::nullopt);
	std::vector<uint8_t> decrypt(std::span<const uint8_t> data, CipherMode mode, std::optional<std::span<const uint8_t, 16>> IV = std::nullopt);
	// std::span<const uint8_t> encrypt(std::span<const uint8_t> data, CipherMode mode, std::optional<std::span<const uint8_t, 16>> IV = std::nullopt);
	// std::span<const uint8_t> decrypt(std::span<const uint8_t> data, CipherMode mode, std::optional<std::span<const uint8_t, 16>> IV = std::nullopt);

	//std::span<const uint8_t> ENCRYPTION_ECB(std::span<const uint8_t> data);
    // std::span<const uint8_t> ENCRYPTION_CTR(std::span<const uint8_t> data,std::span<const uint8_t, 16> IV);
	// std::span<const uint8_t> ENCRYPTION_MAC(std::span<const uint8_t> data);

	// std::span<const uint8_t> DECRYPTION_ECB(std::span<const uint8_t> data);
    // std::span<const uint8_t> DECRYPTION_CTR(std::span<const uint8_t> data,std::span<const uint8_t, 16> IV);

	std::vector<uint8_t> ENCRYPTION_ECB(std::span<const uint8_t> data);
	std::vector<uint8_t> ENCRYPTION_CTR(std::span<const uint8_t> data,std::span<const uint8_t, 16> IV);
	std::vector<uint8_t> ENCRYPTION_MAC(std::span<const uint8_t> data);

	std::vector<uint8_t> DECRYPTION_ECB(std::span<const uint8_t> data);
    std::vector<uint8_t> DECRYPTION_CTR(std::span<const uint8_t> data,std::span<const uint8_t, 16> IV);
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


	// Encrypts contents of a file
	void encrypt_file(const std::string&, const std::string&, const std::string & = "");
	// Decrypts contents of a file
	void decrypt_file(const std::string&, const std::string&, const std::string & = "");

	// Reads a file and returns its contents as a string
	std::string read_file(const std::string&);
	// Writes a string to a file
	void write_to_file(const std::string&, const std::string&);
private:
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	void SetRoundKeys(const uint8_t* data, size_t size);
	std::array<uint32_t, 4> ENCRYPT_BLOCK(std::array<uint32_t, 4> X);
	std::array<uint32_t, 4> DECRYPT_BLOCK(std::array<uint32_t, 4> Y);


	uint32_t ShLo(uint32_t word, uint8_t r);
	uint32_t ShHi(uint32_t word, uint8_t r); 
	uint32_t RotHi(uint32_t word, uint8_t r);
	uint32_t G_func(uint32_t block, uint8_t r);
	std::array<uint8_t, 4> Split32to8(uint32_t block);
	uint32_t Connect8to32(std::array<uint8_t, 4>block);
	uint8_t H_func(uint8_t word);


	uint32_t bytes_to_u32(const uint8_t* p);
	std::array<uint8_t, 4> u32_to_bytes(uint32_t x);
	std::array<uint32_t, 4> bytes_to_u32x4_block(const uint8_t* p);
	std::array<uint8_t, 16> u32x4_block_to_bytes(const std::array<uint32_t, 4>& block);
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	// Linear transformations (used in MAC mode)
	std::string phi1(const std::string&);
	std::string phi2(const std::string&);
	std::string psi(const std::string&);


	uint32_t ROUND_KEY[56]{};
	CipherMode mode;
};