#include <iostream>
#include "../include/Hasher.h"
#include "../include/test_suite.h"
#include "../include/RSA.h"
#include <cassert>
#include <iostream>
#include <stdio.h>
#include <string.h>


int main() {
  std::cout << "\n";
  std::cout << "╔════════════════════════════════════════════════════════════╗\n";
  std::cout << "║      CRYPTOGRAPHY & HASHING MODULE DEMONSTRATION           ║\n";
  std::cout << "╚════════════════════════════════════════════════════════════╝\n";
  std::cout << "\n";

  // Quick demo of hashing
  std::cout << "=== QUICK HASHING DEMO ===\n\n";

  std::string name = "Youssuf Hichri";
  std::string md5_hash = md5_string(name);
  std::string sha256_hash = sha256_string(name);

  std::cout << "Name: " << name << "\n";
  std::cout << "MD5:    " << md5_hash << "\n";
  std::cout << "SHA256: " << sha256_hash << "\n";



  RSAKeyPair keys = generate_rsa_keypair(2048);
  assert(!keys.public_key_pem.empty());
  assert(!keys.private_key_pem.empty());

  const char* message = "Hello, RSA!";
  std::string encrypted = rsa_encrypt_public(keys.public_key_pem, (unsigned char*)message,
                                             strlen(message));

  std::vector<unsigned char> decrypted = rsa_decrypt_private(keys.private_key_pem, encrypted);

  assert(memcmp(message, decrypted.data(), strlen(message)) == 0);

  save_public_key("test_pub.pem", keys.public_key_pem);
  save_private_key("test_priv.pem", keys.private_key_pem);
  std::string loaded_pub = load_public_key("test_pub.pem");
  assert(loaded_pub == keys.public_key_pem);

  // Run comprehensive test suite
  std::cout << "\n\nStarting comprehensive test suite...\n";

  return run_encryption_tests();
}
