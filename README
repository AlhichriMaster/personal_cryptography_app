# Cryptography CLI Application

A comprehensive command-line cryptography toolkit built in C++ with OpenSSL, providing symmetric encryption, asymmetric encryption, hashing, and digital signature capabilities.

## Demo
Check out my demo for the project on youtube: [Demo Link](https://youtu.be/AMcppOT4lYk)


## Features

### 🔐 Symmetric Encryption
- **AES-256-CBC-CTS**: Industry-standard encryption with PBKDF2 key derivation
- **Blowfish-CBC**: Legacy cipher support with PKCS7 padding
- Password-based encryption with automatic algorithm detection during decryption
- Secure key derivation using PBKDF2-HMAC-SHA256 (100,000 iterations)

### 🔑 Asymmetric Cryptography (RSA)
- RSA key pair generation (2048-bit and 4096-bit)
- Public key encryption with OAEP padding
- Private key decryption
- PEM format key storage with restricted file permissions
- Secure key management practices

### 🛡️ Digital Signatures
- RSA signature creation using SHA-256 hashing
- Signature verification for data integrity and authenticity
- Detached signature file format (.sig)
- Support for signing and verifying files of any size

### 🔢 Cryptographic Hashing
- SHA-256 hashing for strings and files
- MD5 hashing for strings and files
- Raw binary hash output support
- Hexadecimal hash representation

## Technical Implementation

### Architecture
- Modular design with separate components for encryption, hashing, RSA operations, and signatures
- Command-line interface with option parsing and comprehensive help system
- Error handling with detailed user feedback
- Resource cleanup using RAII principles

### Security Features
- Automatic detection of encryption algorithms from file headers
- Base64 encoding for binary data transmission
- Private key files with restricted permissions (0600 on Unix)
- Secure random number generation using OpenSSL's RAND_bytes
- Memory cleanup for sensitive key material

### Dependencies
- **OpenSSL 3.x**: Cryptographic operations
- **C++17**: Modern C++ features
- **GCC/G++**: Compilation

## Building

```bash
# Compile the application
make

# Clean build artifacts
make clean

# Run the application
./crypto help
```

## Usage Examples

### Hashing
```bash
# Hash a string with SHA-256
crypto hash -a sha256 -s "Hello World"

# Hash a file with MD5
crypto hash -a md5 -f document.pdf
```

### Symmetric Encryption
```bash
# Encrypt file with AES
crypto encrypt -a aes -f secret.txt -p mypassword

# Encrypt file with Blowfish
crypto encrypt -a blowfish -f data.bin -p pass123 -o data.encrypted

# Decrypt (auto-detects algorithm)
crypto decrypt -f secret.txt.enc -p mypassword
```

### RSA Operations
```bash
# Generate 2048-bit key pair
crypto keygen -b 2048 -o mykey

# Encrypt small file with RSA
crypto encrypt -a rsa -f message.txt -k mykey_public.pem

# Decrypt with private key
crypto decrypt -f message.txt.enc -k mykey_private.pem
```

### Digital Signatures
```bash
# Sign a file
crypto sign -f document.pdf -k private.pem

# Verify signature
crypto verify -f document.pdf -k public.pem -s document.pdf.sig
```

## File Format Specifications

### Encrypted Files
**AES-256-CBC-CTS:**
```
[Algorithm ID: 1 byte] [Salt: 16 bytes] [IV: 16 bytes] [Ciphertext: variable]
```

**Blowfish-CBC:**
```
[Algorithm ID: 1 byte] [Salt: 16 bytes] [IV: 8 bytes] [Ciphertext: variable]
```

### Signature Files (.sig)
```
SIGNATURE-V1
<base64-encoded-signature>
```

## Security Considerations

- **RSA Encryption Limits**: RSA can only encrypt data smaller than the key size minus padding overhead (~245 bytes for 2048-bit keys). For larger data, use hybrid encryption with AES.
- **Key Storage**: Private keys are stored with restricted permissions (owner read/write only on Unix systems)
- **Password Requirements**: Strong passwords are recommended for symmetric encryption
- **Algorithm Selection**: AES-256 is recommended over Blowfish for new applications

## Project Structure

```
.
├── src/
│   ├── main.cpp           # Application entry point
│   ├── CLI.cpp            # Command-line interface and parsing
│   ├── Encryption.cpp     # Symmetric encryption (AES, Blowfish)
│   ├── Hasher.cpp         # Hashing functions (SHA-256, MD5)
│   ├── RSA.cpp            # RSA key generation and encryption
│   └── Signature.cpp      # Digital signature operations
├── include/               # Header files
├── Makefile              # Build configuration
└── README.md             # Documentation
```

## Author

Youssuf Hichri
