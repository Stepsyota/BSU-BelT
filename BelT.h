#pragma once
#include <iostream>
#include <cstdint>
#include <bitset>
#include <string>
#include <vector>
#include "BelT_modes.h"

class BelT {
	public:
		BelT(const std::string&, CipherMode);

		std::string encrypt(const std::string&);
		std::string decrypt(const std::string&);
	private:
		std::string ENCRYPTION(const std::string&);
		std::string ENCRYPTION_ECB(const std::string&);

		std::string DECRYPTION(const std::string&);
		std::string DECRYPTION_ECB(const std::string&);

		uint32_t WordToNumToWord(uint32_t);
		uint32_t StrToUint(const std::string&, uint32_t);

		uint32_t ShLo(uint32_t);
		uint32_t ShHi(uint32_t);
		uint32_t RotHi(uint32_t);

		uint32_t G_func(uint32_t, uint8_t);
		uint32_t H_func(uint8_t);

		std::vector<std::string> SplitTo128(const std::string&);
		std::vector<uint32_t> Split128To32(const std::string&);
		std::vector<uint8_t> Split32To8(uint32_t word);

		uint32_t Connect8To32(const std::vector<uint8_t>&);
		std::string  Connect32To128(const std::vector<uint32_t>&);
		//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		std::vector<uint32_t> KeyToNum(const std::string&);
		void KeyExpansion(std::vector<uint32_t>&);
		void SetRoundKeys(const std::vector<uint32_t>&);

		uint32_t ROUND_KEY[56]{};
		CipherMode mode;
};