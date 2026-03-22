#pragma once
#include <iostream>
#include <cstdint>
#include <bitset>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>

class BelT {
private:
	// ECB encryption mode
	std::string ENCRYPTION_ECB(const std::string&);
	// CTR encryption mode (requires sync message)
	std::string ENCRYPTION_CTR(const std::string&, const std::string&);
	// MAC (Message Authentication Code) generation
	std::string ENCRYPTION_MAC(const std::string&);


	// ECB decryption mode
	std::string DECRYPTION_ECB(const std::string&);
	// CTR decryption mode (requires sync message)
	std::string DECRYPTION_CTR(const std::string&, const std::string&);
};