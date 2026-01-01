#ifndef RSA_H
#define RSA_H

#include <string>
#include <vector>


struct RSAKeyPair {
  std::string public_key_pem;
  std::string private_key_pem;
};


// Generate key pairs
RSAKeyPair generate_rsa_keypair(int bits = 2048);

//Save keys to files
bool save_public_key(const std::string& filepath, const std::string& pem);
bool save_private_key(const std::string& filepath, const std::string& pem);

//Load keys from files
std::string load_public_key(const std::string& filepath);
std::string load_private_key(const std::string& filepath);

//Encrypt data with public key (returns base64 encoded ciphertext)
std::string rsa_encrypt_public(const std::string& public_key_pem,
                               const unsigned char* data, size_t len);

//Decrypt data with private key (input has to be base64 encoded)
std::vector<unsigned char> rsa_decrypt_private(const std::string& private_key_pem,
                                               const std::string& ciphertext_base64);

#endif
