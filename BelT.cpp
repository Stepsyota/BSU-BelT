#include "BelT.h"

BelT::BelT(std::string key_str){
    if (key_str.size() != 32) {
        std::cout << "Invalid key length\n";
        exit(-1);
    }
    unsigned int KEY[8]{};
    for (int i = 0; i < 8; ++i) {
        unsigned int val = 0;
        for (int j = 0; j < 4; ++j) {
            val |= (static_cast<unsigned char>(key_str[4 * i + j])) << (8 * (3 - j));
        }
        KEY[i] = WordToNumToWord(val);
    }

    for (int i = 0; i < 56; ++i) {
        this->ROUND_KEY[i] = KEY[i % 8];
    }
}

std::vector<unsigned int> BelT::ENCRYPTION(std::vector<unsigned int> WORD) {
    unsigned int a = WordToNumToWord(WORD[0]);
    unsigned int b = WordToNumToWord(WORD[1]);
    unsigned int c = WordToNumToWord(WORD[2]);
    unsigned int d = WordToNumToWord(WORD[3]);
    unsigned int e;

    for (unsigned int i = 1; i < 9; ++i) {
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
    std::vector<unsigned int> Y(4);
    Y[0] = WordToNumToWord(b);
    Y[1] = WordToNumToWord(d);
    Y[2] = WordToNumToWord(a);
    Y[3] = WordToNumToWord(c);
    return Y;
}


//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
std::string BelT::ENCRYPTION_ECB(std::string word) {
    if (word.size() < 16) {
        std::cout << "Invalid size\n";
        exit(-2);
    }
    std::vector<std::string> PARTS = SplitTo128(word);
    int num_blocks = (word.size() + 15) / 16;  // the number of blocks rounded up
    std::string RESULT;
    int length_last_block = word.size() % 16;
    for (int i = 0; i < num_blocks; ++i) {
            if (length_last_block != 0 && i == num_blocks - 2) {
                std::string WORD;
                WORD = Connect32To128(ENCRYPTION(Split128To32(PARTS[i])));
                int length_to_add = 16 - length_last_block;
                std::string r = WORD.substr(length_last_block, length_to_add);
                WORD = WORD.substr(0, length_last_block); //X_N
                RESULT += Connect32To128(ENCRYPTION(Split128To32(PARTS[i + 1] + r))); // X_N-1
                RESULT += WORD;
                break;
            }
            RESULT += Connect32To128(ENCRYPTION(Split128To32(PARTS[i])));
    }
    return RESULT;
}

std::string ENCRYPTION_GCM(std::string word) {
    return "";
}
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
unsigned int BelT::WordToNumToWord(unsigned int word) {
    unsigned int tetr[4]{};
    for (int i = 0; i < 4; ++i) {
        tetr[i] = (word >> (24 - i * 8)) & 0b11111111;
    }
    word = tetr[0] + (tetr[1] << 8) + (tetr[2] << 16) + (tetr[3] << 24);
    return word;
}

unsigned int BelT::ShLo(unsigned int word) {
    return word >> 1;
}
unsigned int BelT::ShHi(unsigned int word) {
    return word << 1;
}
unsigned int BelT::RotHi(unsigned int word) {
    unsigned int result_sh_lo = word;
    for (int i = 0; i < 31; ++i) {
        result_sh_lo = ShLo(result_sh_lo);
    }
    return ShHi(word) ^ result_sh_lo;
}

unsigned int BelT::G_func(unsigned int word, unsigned int r) {
    std::vector<uint8_t> PARTS = Split32To8(word);

    for (int i = 0; i < 4; ++i) {
        PARTS[i] = H_func(PARTS[i]);
    }
    unsigned int result = Connect8To32(PARTS);

    for (int i = 0; i < r; ++i) {
        result = RotHi(result);
    }
    return result;
}
unsigned int BelT::H_func(unsigned int word) {
    unsigned int H_box[16][16] = {
    {0xB1, 0x94, 0xBA, 0xC8, 0x0A, 0x08, 0xF5, 0x3B, 0x36, 0x6D, 0x00, 0x8E, 0x58, 0x4A, 0x5D, 0xE4},
    {0x85, 0x04, 0xFA, 0x9D, 0x1B, 0xB6, 0xC7, 0xAC, 0x25, 0x2E, 0x72, 0xC2, 0x02, 0xFD, 0xCE, 0x0D},
    {0x5B, 0xE3, 0xD6, 0x12, 0x17, 0xB9, 0x61, 0x81, 0xFE, 0x67, 0x86, 0xAD, 0x71, 0x6B, 0x89, 0x0B},
    {0x5C, 0xB0, 0xC0, 0xFF, 0x33, 0xC3, 0x56, 0xB8, 0x35, 0xC4, 0x05, 0xAE, 0xD8, 0xE0, 0x7F, 0x99},
    {0xE1, 0x2B, 0xDC, 0x1A, 0xE2, 0x82, 0x57, 0xEC, 0x70, 0x3F, 0xCC, 0xF0, 0x95, 0xEE, 0x8D, 0xF1},
    {0xC1, 0xAB, 0x76, 0x38, 0x9F, 0xE6, 0x78, 0xCA, 0xF7, 0xC6, 0xF8, 0x60, 0xD5, 0xBB, 0x9C, 0x4F},
    {0xF3, 0x3C, 0x65, 0x7B, 0x63, 0x7C, 0x30, 0x6A, 0xDD, 0x4E, 0xA7, 0x79, 0x9E, 0xB2, 0x3D, 0x31},
    {0x3E, 0x98, 0xB5, 0x6E, 0x27, 0xD3, 0xBC, 0xCF, 0x59, 0x1E, 0x18, 0x1F, 0x4C, 0x5A, 0xB7, 0x93},
    {0xE9, 0xDE, 0xE7, 0x2C, 0x8F, 0x0C, 0x0F, 0xA6, 0x2D, 0xDB, 0x49, 0xF4, 0x6F, 0x73, 0x96, 0x47},
    {0x06, 0x07, 0x53, 0x16, 0xED, 0x24, 0x7A, 0x37, 0x39, 0xCB, 0xA3, 0x83, 0x03, 0xA9, 0x8B, 0xF6},
    {0x92, 0xBD, 0x9B, 0x1C, 0xE5, 0xD1, 0x41, 0x01, 0x54, 0x45, 0xFB, 0xC9, 0x5E, 0x4D, 0x0E, 0xF2},
    {0x68, 0x20, 0x80, 0xAA, 0x22, 0x7D, 0x64, 0x2F, 0x26, 0x87, 0xF9, 0x34, 0x90, 0x40, 0x55, 0x11},
    {0xBE, 0x32, 0x97, 0x13, 0x43, 0xFC, 0x9A, 0x48, 0xA0, 0x2A, 0x88, 0x5F, 0x19, 0x4B, 0x09, 0xA1},
    {0x7E, 0xCD, 0xA4, 0xD0, 0x15, 0x44, 0xAF, 0x8C, 0xA5, 0x84, 0x50, 0xBF, 0x66, 0xD2, 0xE8, 0x8A},
    {0xA2, 0xD7, 0x46, 0x52, 0x42, 0xA8, 0xDF, 0xB3, 0x69, 0x74, 0xC5, 0x51, 0xEB, 0x23, 0x29, 0x21},
    {0xD4, 0xEF, 0xD9, 0xB4, 0x3A, 0x62, 0x28, 0x75, 0x91, 0x14, 0x10, 0xEA, 0x77, 0x6C, 0xDA, 0x1D}
    };
    return H_box[word / 16][word % 16];
}

std::vector<std::string> BelT::SplitTo128(std::string word) {
    int num_blocks = (word.size() + 15) / 16; // the number of blocks rounded up
    std::vector<std::string> PARTS(num_blocks);

    for (int i = 0; i < num_blocks; ++i) {
        int start_part = 16 * i;
        int size_block = std::min(16, static_cast<int>(word.size() - (start_part)));
        PARTS[i] = word.substr(start_part, size_block);
    }
    return PARTS;
}
std::vector<unsigned int> BelT::Split128To32(std::string part) {
    std::vector<unsigned int> WORD(4);
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            WORD[i] |= static_cast<unsigned char>(part[4 * i + j]) << (8 * (3 - j)); // |
        }
    }
    return WORD;
}
std::vector<uint8_t> BelT::Split32To8(unsigned int word) {
    std::vector<uint8_t> result(4);
    for (int i = 0; i < 4; ++i) {
        result[i] = (word >> (32 - (i + 1) * 8)) & 0xFF;
    }
    return result;
}
unsigned int BelT::Connect8To32(std::vector<uint8_t> parts) {
    unsigned int result = 0;
    for (int i = 0; i < 4; ++i) {
        result |= parts[i] << (32 - (i + 1) * 8);
    }
    return result;
}
std::string  BelT::Connect32To128(std::vector<unsigned int> WORD) {
    std::string part;
    for (int i = 0; i < 4; ++i) {
        for (int j = 3; j >= 0; --j) {
            part += static_cast<char>((WORD[i] >> (8 * j)) & 0xFF); //
        }
    }
    return part;
}