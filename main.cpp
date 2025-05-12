#include <iostream>
#include "BelT.h"
#include "tests.h"
#include "BelT_modes.h"

int main()
{

    const std::string key =
        "\xE9\xDE\xE7\x2C\x8F\x0C\x0F\xA6\x2D\xDB\x49\xF4\x6F\x73\x96\x47"s
        "\x06\x07\x53\x16\xED\x24\x7A\x37\x39\xCB\xA3\x83\x03\xA9\x8B\xF6"s;

    const std::string text =
        "\xB1\x94\xBA\xC8\x0A\x08\xF5\x3B\x36\x6D\x00\x8E\x58\x4A\x5D\xE4"s
        "\x85\x04\xFA\x9D\x1B\xB6\xC7\xAC\x25\x2E\x72\xC2\x02\xFD\xCE\x0D"s
        "\x5B\xE3\xD6\x12\x17\xB9\x61\x81\xFE\x67\x86\xAD\x71\x6B\x89\x0B"s;

    const std::string text1 =
        "\xB1\x94\xBA\xC8\x0A\x08\xF5\x3B\x36\x6D\x00\x8E\x58"s;
    BelT enc(key, CipherMode::ECB);

    std::cout << "Tests for encryption:\n";
    std::cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";
    std::string mac = enc.belt_mac(text1);
    //std::string decrypted = enc.decrypt(encrypted, iv);
    std::cout << "X:\t\t"; print_str_hex(text1);
    std::cout << "Y:\t\t"; print_str_hex(mac);
    //std::cout << "X decrypted:\t"; print_str_hex(decrypted);

    //tests();
    return 0;
}