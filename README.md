# BelT Cipher Implementation (C++)

**Brief:** Implementation of the Belarusian block cipher **BelT** with support for **ECB**, **CTR**, and **MAC** modes, written in **C++23** and covered with tests.

## 🚀 Features
- Encrypt/decrypt byte buffers  
- Supported modes:
  - **ECB** — Electronic Codebook  
  - **CTR** — Counter (requires IV)  
  - **MAC** — Message Authentication Code (64-bit tag)  
- Supports 128, 192, and 256-bit keys  
- Covered with official ECB test vectors  

## 🧩 Technologies
- **C++23**  
- Standard libraries (`<vector>`, `<span>`, `<array>`, `<optional>`…)

## ⚙️ Usage
- Include `BelT.h` and link the library.  
- Initialize the cipher with a fixed-size key:
```cpp
std::array<uint8_t, 16> key = { /* ... */ };
BelT belt(key);
std::vector<uint8_t> data = { /* ... */ };
```
- Encrypt data:
```cpp
std::vector<uint8_t> cipher = belt.encrypt_ecb(data);
```
- Decrypt data:
```cpp
std::vector<uint8_t> text = belt.decrypt_ecb(cipher);
```
- Or use the mode dispatcher:
```cpp
std::vector<uint8_t> cipher = belt.encrypt(data, CipherMode::ECB);
```
- Encrypt/decrypt files:
```cpp
belt.encrypt_file("plain.bin", "cipher.bin", CipherMode::ECB);
belt.decrypt_file("cipher.bin", "plain.bin", CipherMode::ECB);
```

## 🧪 Tests
- ECB encryption/decryption
- Official ECB test vectors

## ⚠️ Notes
- Keys must be exactly 128, 192, or 256 bits  
- CTR mode requires a 128-bit IV  
