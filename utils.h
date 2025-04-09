#pragma once
#include <iostream>
#include <cstdint>

uint8_t* Split32to8(unsigned int word);
unsigned int Connect8to32(uint8_t parts[]);
unsigned int WordToNum(unsigned int word);
unsigned int NumToWord(unsigned int word);