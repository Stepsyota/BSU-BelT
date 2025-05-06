#include "tests.h"

void tests() {
    BelT enc("\xE9\xDE\xE7\x2C\x8F\x0C\x0F\xA6\x2D\xDB\x49\xF4\x6F\x73\x96\x47\x06\x07\x53\x16\xED\x24\x7A\x37\x39\xCB\xA3\x83\x03\xA9\x8B\xF6");
    std::string word_0 = "\xB1\x94\xBA\xC8\x0A\x08\xF5\x3B\x36\x6D\x00\x8E\x58\x4A\x5D\xE4"s;
    std::string word_ecb_1 = "\xB1\x94\xBA\xC8\x0A\x08\xF5\x3B\x36\x6D\x00\x8E\x58\x4A\x5D\xE4\x85\x04\xFA\x9D\x1B\xB6\xC7\xAC\x25\x2E\x72\xC2\x02\xFD\xCE\x0D\x5B\xE3\xD6\x12\x17\xB9\x61\x81\xFE\x67\x86\xAD\x71\x6B\x89\x0B"s;
    std::string word_ecb_2 = "\xB1\x94\xBA\xC8\x0A\x08\xF5\x3B\x36\x6D\x00\x8E\x58\x4A\x5D\xE4\x85\x04\xFA\x9D\x1B\xB6\xC7\xAC\x25\x2E\x72\xC2\x02\xFD\xCE\x0D\x5B\xE3\xD6\x12\x17\xB9\x61\x81\xFE\x67\x86\xAD\x71\x6B\x89"s;

    std::cout << "Tests for encryption:\n";
    std::cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";
    RunTest_ENC(enc, word_0, "69cca1c9 3557c9e3 d66bc3e0 fa88fa6e");
    std::cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";
    RunTest_ENC_ECB(enc, word_ecb_1, "69cca1c9 3557c9e3 d66bc3e0 fa88fa6e 5f23102e f1097107 75017f73 806da9dc 46fb2ed2 ce771f26 dcb5e5d1 569f9ab0");
    std::cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";
    RunTest_ENC_ECB(enc, word_ecb_2, "69cca1c9 3557c9e3 d66bc3e0 fa88fa6e 36f00cfe d6d1ca14 98c12798 f4beb207 5f23102e f1097107 75017f73 806da9");
    std::cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";

    std::cout << "Tests for decryption:\n";
    std::cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";
    BelT enc1("\x92\xBD\x9B\x1C\xE5\xD1\x41\x01\x54\x45\xFB\xC9\x5E\x4D\x0E\xF2\x68\x20\x80\xAA\x22\x7D\x64\x2F\x26\x87\xF9\x34\x90\x40\x55\x11");
    std::string word_decr_0 = "\xE1\x2B\xDC\x1A\xE2\x82\x57\xEC\x70\x3F\xCC\xF0\x95\xEE\x8D\xF1"s;
    std::string word_ecb_decr_1 = "\xE1\x2B\xDC\x1A\xE2\x82\x57\xEC\x70\x3F\xCC\xF0\x95\xEE\x8D\xF1\xC1\xAB\x76\x38\x9F\xE6\x78\xCA\xF7\xC6\xF8\x60\xD5\xBB\x9C\x4F\xF3\x3C\x65\x7B\x63\x7C\x30\x6A\xDD\x4E\xA7\x79\x9E\xB2\x3D\x31"s;
    std::string word_ecb_decr_2 = "\xE1\x2B\xDC\x1A\xE2\x82\x57\xEC\x70\x3F\xCC\xF0\x95\xEE\x8D\xF1\xC1\xAB\x76\x38\x9F\xE6\x78\xCA\xF7\xC6\xF8\x60\xD5\xBB\x9C\x4F\xF3\x3C\x65\x7B"s;
    
    RunTest_DEC(enc1, word_decr_0, "0dc53006 00cab840 b38448e5 e993f421");
    std::cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";
    RunTest_DEC_ECB(enc1, word_ecb_decr_1, "0dc53006 00cab840 b38448e5 e993f421 e55a239f 2ab5c5d5 fdb6e81b 40938e2a 54120ca3 e6e19c7a d750fc35 31daeab7");
    std::cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";
    RunTest_DEC_ECB(enc1, word_ecb_decr_2, "0dc53006 00cab840 b38448e5 e993f421 5780a6e2 b69eafbb 258726d7 b6718523 e55a239f");
    std::cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";
}
void RunTest_ENC(BelT& enc, const std::string& input, const std::string& expected) {
    std::string encrypted = enc.ENCRYPTION(input);
    std::string decrypted = enc.DECRYPTION(encrypted);
    std::cout << "X:\t\t"; print_str_hex(input);
    std::cout << "Y:\t\t"; print_str_hex(encrypted);
    std::cout << "Y reference:\t" << expected << "\n";
    std::cout << "X decrypted:\t"; print_str_hex(decrypted);
    if (input == decrypted) {
        std::cout << "Test passed!\n";
    }
    else {
        std::cout << "Test failed!\n";
    }
}
void RunTest_ENC_ECB(BelT& enc, const std::string& input, const std::string& expected) {
    std::string encrypted = enc.ENCRYPTION_ECB(input);
    std::string decrypted = enc.DECRYPTION_ECB(encrypted);
    std::cout << "X:\t\t"; print_str_hex(input);
    std::cout << "Y:\t\t"; print_str_hex(encrypted);
    std::cout << "Y reference:\t" << expected << "\n";
    std::cout << "X decrypted:\t"; print_str_hex(decrypted);
    if (input == decrypted) {
        std::cout << "Test passed!\n";
    }
    else {
        std::cout << "Test failed!\n";
    }
}
void RunTest_DEC(BelT& enc, const std::string& input, const std::string& expected) {
    std::string decrypted = enc.DECRYPTION(input);
    std::string encrypted = enc.ENCRYPTION_ECB(decrypted);
    std::cout << "Y:\t\t"; print_str_hex(input);
    std::cout << "X:\t\t"; print_str_hex(decrypted);
    std::cout << "X reference:\t" << expected << "\n";
    std::cout << "Y encrypted:\t"; print_str_hex(encrypted);
    if (input == encrypted) {
        std::cout << "Test passed!\n";
    }
    else {
        std::cout << "Test failed!\n";
    }
}
void RunTest_DEC_ECB(BelT& enc, const std::string& input, const std::string& expected) {
    std::string decrypted = enc.DECRYPTION_ECB(input);
    std::string encrypted = enc.ENCRYPTION_ECB(decrypted);
    std::cout << "Y:\t\t"; print_str_hex(input);
    std::cout << "X:\t\t"; print_str_hex(decrypted);
    std::cout << "X reference:\t" << expected << "\n";
    std::cout << "Y encrypted:\t"; print_str_hex(encrypted);
    if (input == encrypted) {
        std::cout << "Test passed!\n";
    }
    else {
        std::cout << "Test failed!\n";
    }
}

void print_str_hex(std::string str) {
    for (int i = 0; i < str.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(static_cast<unsigned char>(str[i]));
        if ((i + 1) % 4 == 0) std::cout << " ";
    }
    std::cout << std::endl;
}