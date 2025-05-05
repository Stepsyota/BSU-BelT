#include "tests.h"

void tests() {
    BelT enc("\xE9\xDE\xE7\x2C\x8F\x0C\x0F\xA6\x2D\xDB\x49\xF4\x6F\x73\x96\x47\x06\x07\x53\x16\xED\x24\x7A\x37\x39\xCB\xA3\x83\x03\xA9\x8B\xF6");
    std::string word_ecb_0 = "\xB1\x94\xBA\xC8\x0A\x08\xF5\x3B\x36\x6D\x00\x8E\x58\x4A\x5D\xE4"s;
    std::string word_ecb_1 = "\xB1\x94\xBA\xC8\x0A\x08\xF5\x3B\x36\x6D\x00\x8E\x58\x4A\x5D\xE4\x85\x04\xFA\x9D\x1B\xB6\xC7\xAC\x25\x2E\x72\xC2\x02\xFD\xCE\x0D\x5B\xE3\xD6\x12\x17\xB9\x61\x81\xFE\x67\x86\xAD\x71\x6B\x89\x0B"s;
    std::string word_ecb_2 = "\xB1\x94\xBA\xC8\x0A\x08\xF5\x3B\x36\x6D\x00\x8E\x58\x4A\x5D\xE4\x85\x04\xFA\x9D\x1B\xB6\xC7\xAC\x25\x2E\x72\xC2\x02\xFD\xCE\x0D\x5B\xE3\xD6\x12\x17\xB9\x61\x81\xFE\x67\x86\xAD\x71\x6B\x89"s;

    std::cout << "Tests for encryption:\n";
    std::cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";
    std::string r = enc.ENCRYPTION_ECB(word_ecb_0);
    std::cout << "First example:\n";
    std::cout << "X:\t";  print_str_hex(word_ecb_0);
    std::cout << "Y:\t";  print_str_hex(r);
    std::cout << "Yref:\t69CCA1C9 3557C9E3 D66BC3E0 FA88FA6E\n";
    r = enc.DECRYPTION_ECB(r);
    std::cout << "X:\t"; print_str_hex(r);
    if (word_ecb_0 == r) {
        std::cout << "The test was passed\n";
    }
    else {
        std::cout << "The test was failed\n";
    }

    std::cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";

    r = enc.ENCRYPTION_ECB(word_ecb_1);
    std::cout << "Second example:\n";
    std::cout << "X:\t"; print_str_hex(word_ecb_1);
    std::cout << "Y:\t"; print_str_hex(r);
    std::cout << "Yref:\t69CCA1C9 3557C9E3 D66BC3E0 FA88FA6E 5F23102E F1097107 75017F73 806DA9DC 46FB2ED2 CE771F26 DCB5E5D1 569F9AB0\n";
    r = enc.DECRYPTION_ECB(r);
    std::cout << "X:\t"; print_str_hex(r);
    if (word_ecb_1 == r) {
        std::cout << "The test was passed\n";
    }
    else {
        std::cout << "The test was failed\n";
    }

    std::cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";

    r = enc.ENCRYPTION_ECB(word_ecb_2);
    std::cout << "Third example:\n";
    std::cout << "X:\t"; print_str_hex(word_ecb_2);
    std::cout << "Y:\t"; print_str_hex(r);
    std::cout << "Yref:\t69CCA1C9 3557C9E3 D66BC3E0 FA88FA6E 36F00CFE D6D1CA14 98C12798 F4BEB207 5F23102E F1097107 75017F73 806DA9\n";
    std::cout << "X:\t"; r = enc.DECRYPTION_ECB(r);
    print_str_hex(r);
    if (word_ecb_2 == r) {
        std::cout << "The test was passed\n";
    }
    else {
        std::cout << "The test was failed\n";
    }
    std::cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";

    std::cout << "Tests for decryption:\n";
    std::cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";
    BelT enc1("\x92\xBD\x9B\x1C\xE5\xD1\x41\x01\x54\x45\xFB\xC9\x5E\x4D\x0E\xF2\x68\x20\x80\xAA\x22\x7D\x64\x2F\x26\x87\xF9\x34\x90\x40\x55\x11");
    std::string word_ecb_decr_0 = "\xE1\x2B\xDC\x1A\xE2\x82\x57\xEC\x70\x3F\xCC\xF0\x95\xEE\x8D\xF1"s;
    std::string word_ecb_decr_1 = "\xE1\x2B\xDC\x1A\xE2\x82\x57\xEC\x70\x3F\xCC\xF0\x95\xEE\x8D\xF1\xC1\xAB\x76\x38\x9F\xE6\x78\xCA\xF7\xC6\xF8\x60\xD5\xBB\x9C\x4F\xF3\x3C\x65\x7B\x63\x7C\x30\x6A\xDD\x4E\xA7\x79\x9E\xB2\x3D\x31"s;
    std::string word_ecb_decr_2 = "\xE1\x2B\xDC\x1A\xE2\x82\x57\xEC\x70\x3F\xCC\xF0\x95\xEE\x8D\xF1\xC1\xAB\x76\x38\x9F\xE6\x78\xCA\xF7\xC6\xF8\x60\xD5\xBB\x9C\x4F\xF3\x3C\x65\x7B"s;

    r = enc1.DECRYPTION_ECB(word_ecb_decr_0);
    std::cout << "First example:\n";
    std::cout << "Y:\t";  print_str_hex(word_ecb_decr_0);
    std::cout << "X:\t";  print_str_hex(r);
    std::cout << "Xref:\t0DC53006 00CAB840 B38448E5 E993F421\n";
    r = enc1.ENCRYPTION_ECB(r);
    std::cout << "Y:\t"; print_str_hex(r);
    if (word_ecb_decr_0 == r) {
        std::cout << "The test was passed\n";
    }
    else {
        std::cout << "The test was failed\n";
    }

    std::cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";

    std::cout << "Second example:\n";
    std::cout << "Y:\t";  print_str_hex(word_ecb_decr_1);
    r = enc1.DECRYPTION_ECB(word_ecb_decr_1);
    std::cout << "X:\t";  print_str_hex(r);
    std::cout << "Xref:\t0DC53006 00CAB840 B38448E5 E993F421 E55A239F 2AB5C5D5 FDB6E81B 40938E2A 54120CA3 E6E19C7A D750FC35 31DAEAB7\n";
    r = enc1.ENCRYPTION_ECB(r);
    std::cout << "Y:\t"; print_str_hex(r);
    if (word_ecb_decr_1 == r) {
        std::cout << "The test was passed\n";
    }
    else {
        std::cout << "The test was failed\n";
    }

    std::cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";

    std::cout << "Third example:\n";
    std::cout << "Y:\t";  print_str_hex(word_ecb_decr_2);
    r = enc1.DECRYPTION_ECB(word_ecb_decr_2);
    std::cout << "X:\t";  print_str_hex(r);
    std::cout << "Xref:\t0DC53006 00CAB840 B38448E5 E993F421 5780A6E2 B69EAFBB 258726D7 B6718523 E55A239F\n";
    r = enc1.ENCRYPTION_ECB(r);
    std::cout << "Y:\t"; print_str_hex(r);
    if (word_ecb_decr_2 == r) {
        std::cout << "The test was passed\n";
    }
    else {
        std::cout << "The test was failed\n";
    }

    std::cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";
}
void print_str_hex(std::string str) {
    for (int i = 0; i < str.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(static_cast<unsigned char>(str[i]));
        if ((i + 1) % 4 == 0) std::cout << " ";
    }
    std::cout << std::endl;
}