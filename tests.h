#pragma once
#include <iostream>
#include <iomanip>

#include "BelT.h"

using namespace std::string_literals;

void tests();
void RunTest_HugeText_();
void RunTests_ECB_ENC();
void RunTests_ECB_DEC();
void RunOneTest_ENC_ECB(BelT&, const std::string&, const std::string&);
void RunOneTest_DEC_ECB(BelT&, const std::string&, const std::string&);
void print_str_hex(std::string);