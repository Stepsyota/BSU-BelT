#pragma once
#include <iostream>
#include <cstdint>
#include <bitset>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>

// Cipher operating modes
enum class CipherMode {
	ECB,    // Electronic Codebook
	CTR,    // Counter mode 
	MAC,    // Message authentication code
};

class BelT {
public:
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