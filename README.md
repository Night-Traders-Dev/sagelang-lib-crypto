# crypto

## Purpose
Comprehensive cryptographic library for secure communication and data protection in SageLang.

## Features
- **Ciphers**: AES and other standard symmetric algorithms.
- **Hashing**: SHA, MD5, and other hashing functions.
- **HMAC**: Message authentication codes.
- **Entropy**: Secure random number generation.

## Usage Example
```sage
import crypto.hash
import crypto.cipher

let h = hash.sha256("data")
let encrypted = cipher.aes_encrypt(data, key)
```
