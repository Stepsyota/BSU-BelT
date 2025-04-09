#include "BelT.h"

unsigned int ENCRYPTION() {
    unsigned int WORD[4]{ 0xB194BAC8, 0x0A08F53B, 0x366D008E, 0x584A5DE4 };
    unsigned int NUMS[4]{};
    for (int i = 0; i < 4; ++i) {
        NUMS[i] = WordToNum(WORD[i]);
    }
    unsigned int KEY_WORD[8]{ 0xE9DEE72C, 0x8F0C0FA6, 0x2DDB49F4, 0x6F739647, 0x06075316, 0xED247A37, 0x39CBA383, 0x03A98BF6 };
    unsigned int KEY[8]{};
    for (int i = 0; i < 8; ++i) {
        KEY[i] = WordToNum(KEY_WORD[i]);
    }
    unsigned int ROUND_KEY[56]{};
    for (int i = 0; i < 56; ++i) {
        ROUND_KEY[i] = KEY[i % 8];
    }
    unsigned int a = NUMS[0];
    unsigned int b = NUMS[1];
    unsigned int c = NUMS[2];
    unsigned int d = NUMS[3];
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
    unsigned int Y[4]{};
    Y[0] = NumToWord(b);
    Y[1] = NumToWord(d);
    Y[2] = NumToWord(a);
    Y[3] = NumToWord(c);

    for (int i = 0; i < 4; ++i) {
        std::cout << std::hex << Y[i] << '\t';
    }
    std::cout << std::endl;
    return 0;
}