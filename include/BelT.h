#pragma once
#include <iostream>
#include <cstdint>
#include <bitset>
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
	static std::expected<BelT, BelTError> create(const std::array<uint8_t, 16>& key);
	static std::expected<BelT, BelTError> create(const std::array<uint8_t, 24>& key);
	static std::expected<BelT, BelTError> create(const std::array<uint8_t, 32>& key);

	BelT();


	// Constructor: takes key and mode
	BelT(const std::string&, CipherMode);

	// Encrypts input string, optionally using sync message
	std::string encrypt(const std::string&, const std::string & = "");
	// Decrypts input string, optionally using sync message
	std::string decrypt(const std::string&, const std::string & = "");

	// Encrypts contents of a file
	void encrypt_file(const std::string&, const std::string&, const std::string & = "");
	// Decrypts contents of a file
	void decrypt_file(const std::string&, const std::string&, const std::string & = "");

	// Reads a file and returns its contents as a string
	std::string read_file(const std::string&);
	// Writes a string to a file
	void write_to_file(const std::string&, const std::string&);
private:

	friend class BelTTester; // тестовый хелпер
	void SetRoundKeys(const uint8_t* data, size_t size);
	std::array<uint32_t, 4> ENCRYPT_BLOCK(std::array<uint32_t, 4> X);
	std::array<uint32_t, 4> DECRYPT_BLOCK(std::array<uint32_t, 4> Y);


	uint32_t ShLoNEW(uint32_t word, uint8_t r);
	uint32_t ShHiNEW(uint32_t word, uint8_t r); 
	uint32_t RotHiNEW(uint32_t word, uint8_t r);
	uint32_t G_funcNEW(uint32_t block, uint8_t r);
	std::array<uint8_t, 4> Split32to8NEW(uint32_t block);
	uint32_t Connect8to32NEW(std::array<uint8_t, 4>block);
	uint8_t H_funcNEW(uint8_t word);

	// Encrypts one 128-bit block
	std::string ENCRYPT_ONE_BLOCK(const std::string&);

	// ECB encryption mode
	std::string ENCRYPTION_ECB(const std::string&);
	// CTR encryption mode (requires sync message)
	std::string ENCRYPTION_CTR(const std::string&, const std::string&);
	// MAC (Message Authentication Code) generation
	std::string ENCRYPTION_MAC(const std::string&);

	// Decrypts one 128-bit block
	std::string DECRYPT_ONE_BLOCK(const std::string&);

	// ECB decryption mode
	std::string DECRYPTION_ECB(const std::string&);
	// CTR decryption mode (requires sync message)
	std::string DECRYPTION_CTR(const std::string&, const std::string&);

	// Byte permutation and conversion utilities
	uint32_t WordToNumToWord(uint32_t);
	uint32_t StrToUint(const std::string&, uint32_t);

	// Linear transformations (used in MAC mode)
	std::string phi1(const std::string&);
	std::string phi2(const std::string&);
	std::string psi(const std::string&);

	// XOR two binary strings
	std::string xor_strings(const std::string&, const std::string&);

	// Bit shifts and rotations
	uint32_t ShLo(uint32_t);
	uint32_t ShHi(uint32_t);
	uint32_t RotHi(uint32_t);

	// Core nonlinear transformations
	uint32_t G_func(uint32_t, uint8_t);
	uint32_t H_func(uint8_t);

	// Splits input into 128-bit blocks
	std::vector<std::string> SplitTo128(const std::string&);
	// Splits 128-bit block into four 32-bit words
	std::vector<uint32_t> Split128To32(const std::string&);
	// Splits 32-bit word into four bytes
	std::vector<uint8_t> Split32To8(uint32_t word);

	// Combines four bytes into a 32-bit word
	uint32_t Connect8To32(const std::vector<uint8_t>&);
	// Combines four 32-bit words into a 128-bit block
	std::string  Connect32To128(const std::vector<uint32_t>&);
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	// Converts key string to numeric form
	std::vector<uint32_t> KeyToNum(const std::string&);
	// Performs key expansion
	void KeyExpansion(std::vector<uint32_t>&);
	// Sets round keys
	void SetRoundKeys(const std::vector<uint32_t>&);

	uint32_t ROUND_KEY[56]{};
	CipherMode mode;
};

class BelTTester {
public:
    static void print_round_keys(const BelT& b1, const BelT& b2) {
		std::print("START\n");
        for (int k = 0; k < 56; ++k) {
            //std::cout << std::hex << b1.ROUND_KEY[k] << ' ';
			std::print("{:#08X} == {:#08X} {}\n", b1.ROUND_KEY[k], b2.ROUND_KEY[k], b1.ROUND_KEY[k] == b2.ROUND_KEY[k]);
        }
		std::print("\nEND\n");
    }

	static void print_blocks(BelT& b1, BelT& b2, std::string & word1, std::array<uint32_t, 4> & word2) {
		std::print("START\n");
		std::print("First word:\t");
		for (size_t i = 0; i < word1.size(); ++i)
		{
			std::print("{:02X}", static_cast<uint8_t>(word1[i]));

			if ((i + 1) % 4 == 0)
				std::print("\t");
		}		
		std::print("\n");
		std::print("Second word:\t");
		for (auto i : word2)
		{
			std::print("{:08X}\t", i);
		}

		std::print("\n");

		std::string encrypted = b1.ENCRYPT_ONE_BLOCK(word1);
		std::print("First enc word:\t");
		for (size_t i = 0; i < encrypted.size(); ++i)
		{
			std::print("{:02X}", static_cast<uint8_t>(encrypted[i]));

			if ((i + 1) % 4 == 0)
				std::print("\t");
		}		
		std::print("\n");
		
		std::array<uint32_t, 4> encrypted_2 = b2.ENCRYPT_BLOCK(word2);
		std::print("Sec enc word:\t");
		for (auto i : encrypted_2)
		{
			std::print("{:08X}\t", i);
		}

		std::print("\n");

		std::string decrypted = b1.DECRYPT_ONE_BLOCK(encrypted);
		std::print("First enc word:\t");
		for (size_t i = 0; i < decrypted.size(); ++i)
		{
			std::print("{:02X}", static_cast<uint8_t>(decrypted[i]));

			if ((i + 1) % 4 == 0)
				std::print("\t");
		}		
		std::print("\n");
		
		std::array<uint32_t, 4> decrypted_2 = b2.DECRYPT_BLOCK(encrypted_2);
		std::print("Sec enc word:\t");
		for (auto i : decrypted_2)
		{
			std::print("{:08X}\t", i);
		}

		std::print("\nEND\n");
    }
};