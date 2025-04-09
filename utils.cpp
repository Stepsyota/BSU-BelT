#include "utils.h"

uint8_t* Split32to8(unsigned int word) {
    uint8_t* result = new uint8_t[4];
    for (int i = 0; i < 4; ++i) {
        result[i] = (word >> (32 - (i + 1) * 8)) & 0xFF;
    }
    return result;
}
unsigned int Connect8to32(uint8_t parts[]) {
    unsigned int result = 0;
    for (int i = 0; i < 4; ++i) {
        result = result ^ (parts[i] << (32 - (i + 1) * 8));
    }
    return result;
}

unsigned int WordToNum(unsigned int word) {
    unsigned int tetr[4]{};
    for (int i = 0; i < 4; ++i) {
        tetr[i] = (word >> (24 - i * 8)) & 0b11111111;
        //std::cout << std::hex << tetr[i] << std::endl;
    }
    word = tetr[0] + 256 * tetr[1] + 65536 * tetr[2] + 16777216 * tetr[3];
    return word;
}

unsigned int NumToWord(unsigned int word) {
    unsigned int tetr[4]{};
    for (int i = 0; i < 4; ++i) {
        tetr[i] = (word >> (24 - i * 8)) & 0b11111111;
        //std::cout << std::hex << tetr[i] << std::endl;
    }
    word = tetr[0] + 256 * tetr[1] + 65536 * tetr[2] + 16777216 * tetr[3];
    return word;
}