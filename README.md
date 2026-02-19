# BelT Cipher Implementation (C++)

**Brief:** Implementation of the Belarusian block cipher **BelT** with support for **ECB**, **CTR**, and **MAC** modes, written in **C++** and covered with tests.

## 🚀 Features
- Encrypt/decrypt strings and files  
- Supported modes:
  - **ECB** — Electronic Codebook  
  - **CTR** — Counter (requires IV)  
  - **MAC** — Message Authentication Code (64-bit tag)  
- Supports 128, 192, and 256-bit keys  
- Fully tested with blocks, large texts, and files  

## 🧩 Technologies
- **C++17**  
- Standard libraries (`<vector>`, `<string>`, `<fstream>`…)  

## ⚙️ Usage
- Include `BelT.h` and `BelT.cpp` in your project.  
- Initialize the cipher:
```cpp
BelT belt("mysecretkey12345", CipherMode::ECB);
```
- Encrypt a string:
```cpp
std::string cipher = belt.encrypt("Hello world!");
```
- Decrypt:
```cpp
std::string text = belt.decrypt(cipher, "");
```
- Encrypt/decrypt files:
```cpp
belt.encrypt_file("plain.txt", "cipher.bin", "");
belt.decrypt_file("cipher.bin", "decrypted.txt", "");
```

## 🧪 Tests
- ECB encryption/decryption
- CTR encryption/decryption
- MAC tag generation
- Large text handling
- File encryption/decryption

## ⚠️ Notes
- Keys must be exactly 128, 192, or 256 bits  
- CTR mode requires a 128-bit IV  
