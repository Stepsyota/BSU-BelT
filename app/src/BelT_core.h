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

private:
	// Encrypts one 128-bit block
	std::string ENCRYPT_ONE_BLOCK(const std::string&);

	// Decrypts one 128-bit block
	std::string DECRYPT_ONE_BLOCK(const std::string&);

	uint32_t ROUND_KEY[56]{};
	CipherMode mode;
};