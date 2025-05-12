#pragma once
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>

#include "BelT.h"

using namespace std::string_literals;

// Runs all available tests
void tests();

// Runs a test with large input data
void RunTest_HugeText_();

// Runs all ECB encryption tests
void RunTests_ECB_ENC();
// Runs one ECB encryption test
void RunOneTest_ENC_ECB(BelT&, const std::string&, const std::string&);

// Runs all ECB decryption tests
void RunTests_ECB_DEC();
// Runs one ECB decryption test
void RunOneTest_DEC_ECB(BelT&, const std::string&, const std::string&);

// Runs all CTR mode tests
void RunCTRTests();

// Runs all MAC generation tests
void RunMACTEsts();

// Prints a string in hexadecimal format
void print_str_hex(std::string str);

// Runs file encryption and decryption test
void RunTest_File_Encryption_Decryption();