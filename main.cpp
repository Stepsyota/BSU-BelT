#include <iostream>
#include "BelT.h"
#include <iomanip>
using namespace std::string_literals;
int main()
{
    BelT enc("\xE9\xDE\xE7\x2C\x8F\x0C\x0F\xA6\x2D\xDB\x49\xF4\x6F\x73\x96\x47\x06\x07\x53\x16\xED\x24\x7A\x37\x39\xCB\xA3\x83\x03\xA9\x8B\xF6");

    std::string word_enc_1 = "\xB1\x94\xBA\xC8\x0A\x08\xF5\x3B\x36\x6D\x00\x8E\x58\x4A\x5D\xE4"s;
    std::string word_ecb_1 = "\xB1\x94\xBA\xC8\x0A\x08\xF5\x3B\x36\x6D\x00\x8E\x58\x4A\x5D\xE4\x85\x04\xFA\x9D\x1B\xB6\xC7\xAC\x25\x2E\x72\xC2\x02\xFD\xCE\x0D\x5B\xE3\xD6\x12\x17\xB9\x61\x81\xFE\x67\x86\xAD\x71\x6B\x89\x0B"s;
    std::string word_ecb_2 = "\xB1\x94\xBA\xC8\x0A\x08\xF5\x3B\x36\x6D\x00\x8E\x58\x4A\x5D\xE4\x85\x04\xFA\x9D\x1B\xB6\xC7\xAC\x25\x2E\x72\xC2\x02\xFD\xCE\x0D\x5B\xE3\xD6\x12\x17\xB9\x61\x81\xFE\x67\x86\xAD\x71\x6B\x89"s;
    std::string r = enc.ENCRYPTION_ECB(word_ecb_1);
    std::cout << "First example:\n";
    for (int i = 0; i < r.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(static_cast<unsigned char>(r[i]));
        if ((i + 1) % 4 == 0) std::cout << " ";
    }
    std::cout << std::endl;

    r = enc.ENCRYPTION_ECB(word_ecb_2);
    std::cout << "Second example:\n";
    for (int i = 0; i < r.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(static_cast<unsigned char>(r[i]));
        if ((i + 1) % 4 == 0) std::cout << " ";
    }
    std::cout << std::endl;
    return 0;
}