#pragma once
#include <iostream>
#include <cstdint>
#include <bitset>
#include <string>
#include <vector>

class BelT {
	public:
		BelT(std::string);
		std::vector<unsigned int> ENCRYPTION(std::vector<unsigned int>);
		std::string ENCRYPTION_ECB(std::string);
		std::string ENCRYPTION_GCM(std::string);

		std::vector<unsigned int> DECRYPTION(std::vector<unsigned int>);
		std::string DECRYPTION_ECB(std::string);
	
	private:
		unsigned int WordToNumToWord(unsigned int word);

		unsigned int ShLo(unsigned int);
		unsigned int ShHi(unsigned int);
		unsigned int RotHi(unsigned int);

		unsigned int G_func(unsigned int, unsigned int);
		unsigned int H_func(unsigned int);

		std::vector<std::string> SplitTo128(std::string);
		std::vector<unsigned int> Split128To32(std::string);
		std::vector<uint8_t> Split32To8(unsigned int word);

		unsigned int Connect8To32(std::vector<uint8_t>);
		std::string  Connect32To128(std::vector<unsigned int>);
		//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		unsigned int ROUND_KEY[56]{};
};