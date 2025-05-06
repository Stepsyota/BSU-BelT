#pragma once
#include <iostream>
#include <iomanip>

#include "BelT.h"

using namespace std::string_literals;

void tests();
void RunTest_ENC(BelT&, const std::string&, const std::string&);
void RunTest_ENC_ECB(BelT&, const std::string&, const std::string&);
void RunTest_DEC(BelT&, const std::string&, const std::string&);
void RunTest_DEC_ECB(BelT&, const std::string&, const std::string&);
void print_str_hex(std::string);