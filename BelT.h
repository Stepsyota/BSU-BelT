#pragma once
#include <iostream>
#include <cstdint>
#include <bitset>
#include <string>

class BelT {
	public:
		BelT(std::string);
		unsigned int ENCRYPTION();
	
	private:
		unsigned int G_func(unsigned int, unsigned int);
		unsigned int ShLo(unsigned int);
		unsigned int ShHi(unsigned int);
		unsigned int RotHi(unsigned int);
		unsigned int H_func(unsigned int);
		uint8_t* Split32to8(unsigned int word);
		unsigned int Connect8to32(uint8_t parts[]);
		unsigned int WordToNum(unsigned int word);
		unsigned int NumToWord(unsigned int word);

		unsigned int ROUND_KEY[56]{};
};