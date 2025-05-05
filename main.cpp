#include <iostream>
#include "BelT.h"

int main()
{
    BelT enc("\xE9\xDE\xE7\x2C\x8F\x0C\x0F\xA6\x2D\xDB\x49\xF4\x6F\x73\x96\x47\x06\x07\x53\x16\xED\x24\x7A\x37\x39\xCB\xA3\x83\x03\xA9\x8B\xF6");
    unsigned int WORD[4]{ 0xB194BAC8, 0x0A08F53B, 0x366D008E, 0x584A5DE4 };
    unsigned int r = enc.ENCRYPTION(WORD);
    return 0;
}