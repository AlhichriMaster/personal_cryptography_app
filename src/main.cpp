#include <iostream>
#include "../include/Hasher.h"
#include "../include/test_suite.h"


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

  // Run comprehensive test suite
  std::cout << "\n\nStarting comprehensive test suite...\n";

  return run_encryption_tests();
}
