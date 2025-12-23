#include <iostream>
#include <cstring>
#include <fstream>
#include <vector>
#include "../include/Encryption.h"
#include "../include/Hasher.h"

void print_hex(const unsigned char* data, size_t len, const char* label) {
  printf("%s: ", label);
  for (size_t i = 0; i < len && i < 32; i++) {
    printf("%02x", data[i]);
  }
  if (len > 32) printf("... (%zu more bytes)", len - 32);
  printf("\n");
}

// Helper function to read file into buffer
std::vector<unsigned char> read_file(const std::string& filepath) {
  std::ifstream file(filepath, std::ios::binary | std::ios::ate);
  if (!file) {
    throw std::runtime_error("Cannot open file: " + filepath);
  }

  std::streamsize size = file.tellg();
  file.seekg(0, std::ios::beg);

  std::vector<unsigned char> buffer(size);
  if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
    throw std::runtime_error("Cannot read file: " + filepath);
  }

  return buffer;
}

// Helper function to write buffer to file
bool write_file(const std::string& filepath, const unsigned char* data, size_t len) {
  std::ofstream file(filepath, std::ios::binary);
  if (!file) {
    return false;
  }

  file.write(reinterpret_cast<const char*>(data), len);
  return file.good();
}

// Test string encryption/decryption
int test_string_encryption() {
  const char* password = "MySecurePassword123";
  unsigned char plaintext[] = "This is a secret message that needs to be encrypted!";
  size_t plaintext_len = sizeof(plaintext) - 1;

  printf("\n=== STRING ENCRYPTION TESTS ===\n\n");
  printf("Original message: %s\n", plaintext);
  printf("Message length: %zu bytes\n\n", plaintext_len);

  int failures = 0;

  // Test AES encryption
  printf("--- Test 1: AES-256-CBC-CTS Encryption ---\n");
  unsigned char encrypted_aes[1024];
  size_t encrypted_aes_len;

  if (encrypt_with_password_AES(password, plaintext, plaintext_len,
                                encrypted_aes, &encrypted_aes_len) > 0) {
    printf("✓ AES Encryption succeeded (%zu bytes)\n", encrypted_aes_len);
    printf("  Algorithm ID byte: 0x%02x\n", encrypted_aes[0]);
    print_hex(encrypted_aes, encrypted_aes_len, "  Encrypted data");

    // Decrypt with auto-detection
    unsigned char decrypted_aes[1024];
    size_t decrypted_aes_len;

    if (decrypt_with_password(password, encrypted_aes, encrypted_aes_len,
                              decrypted_aes, &decrypted_aes_len) > 0) {
      decrypted_aes[decrypted_aes_len] = '\0';
      printf("✓ AES Decryption succeeded (auto-detected algorithm)\n");
      printf("  Decrypted: %s\n", decrypted_aes);

      if (memcmp(plaintext, decrypted_aes, plaintext_len) == 0) {
        printf("✓ Decrypted matches original!\n");
      } else {
        printf("✗ ERROR: Decrypted doesn't match!\n");
        failures++;
      }
    } else {
      printf("✗ AES Decryption failed!\n");
      failures++;
    }
  } else {
    printf("✗ AES Encryption failed!\n");
    failures++;
  }

  printf("\n--- Test 2: Blowfish-CBC Encryption ---\n");
  unsigned char encrypted_bf[1024];
  size_t encrypted_bf_len;

  if (encrypt_with_password_BF(password, plaintext, plaintext_len,
                               encrypted_bf, &encrypted_bf_len) > 0) {
    printf("✓ Blowfish Encryption succeeded (%zu bytes)\n", encrypted_bf_len);
    printf("  Algorithm ID byte: 0x%02x\n", encrypted_bf[0]);
    print_hex(encrypted_bf, encrypted_bf_len, "  Encrypted data");

    // Decrypt with auto-detection
    unsigned char decrypted_bf[1024];
    size_t decrypted_bf_len;

    if (decrypt_with_password(password, encrypted_bf, encrypted_bf_len,
                              decrypted_bf, &decrypted_bf_len) > 0) {
      decrypted_bf[decrypted_bf_len] = '\0';
      printf("✓ Blowfish Decryption succeeded (auto-detected algorithm)\n");
      printf("  Decrypted: %s\n", decrypted_bf);

      if (memcmp(plaintext, decrypted_bf, plaintext_len) == 0) {
        printf("✓ Decrypted matches original!\n");
      } else {
        printf("✗ ERROR: Decrypted doesn't match!\n");
        failures++;
      }
    } else {
      printf("✗ Blowfish Decryption failed!\n");
      failures++;
    }
  } else {
    printf("✗ Blowfish Encryption failed!\n");
    failures++;
  }

  printf("\n--- Test 3: Default encrypt (uses AES) ---\n");
  unsigned char encrypted_default[1024];
  size_t encrypted_default_len;

  if (encrypt_with_password(password, plaintext, plaintext_len,
                           encrypted_default, &encrypted_default_len) > 0) {
    printf("✓ Default encryption succeeded\n");
    printf("  Algorithm ID: 0x%02x (should be AES)\n", encrypted_default[0]);

    unsigned char decrypted_default[1024];
    size_t decrypted_default_len;

    if (decrypt_with_password(password, encrypted_default, encrypted_default_len,
                              decrypted_default, &decrypted_default_len) > 0) {
      decrypted_default[decrypted_default_len] = '\0';
      printf("✓ Default decryption succeeded\n");
      printf("  Decrypted: %s\n", decrypted_default);

      if (memcmp(plaintext, decrypted_default, plaintext_len) == 0) {
        printf("✓ Decrypted matches original!\n");
      } else {
        printf("✗ ERROR: Decrypted doesn't match!\n");
        failures++;
      }
    } else {
      printf("✗ Default decryption failed!\n");
      failures++;
    }
  } else {
    printf("✗ Default encryption failed!\n");
    failures++;
  }

  printf("\n--- Test 4: Wrong Password Test ---\n");
  unsigned char wrong_decrypt[1024];
  size_t wrong_decrypt_len;

  if (decrypt_with_password("WrongPassword", encrypted_aes, encrypted_aes_len,
                            wrong_decrypt, &wrong_decrypt_len) > 0) {
    printf("⚠ Decryption with wrong password succeeded (produces garbage)\n");
    printf("  This is expected behavior - authentication would prevent this\n");
  } else {
    printf("✓ Decryption with wrong password failed (good)\n");
  }

  return failures;
}

// Test file encryption/decryption
int test_file_encryption() {
  printf("\n\n=== FILE ENCRYPTION TESTS ===\n\n");

  const char* password = "FileEncryptionPassword456";
  const std::string test_file = "test_data.txt";
  const std::string encrypted_aes_file = "test_data_aes.enc";
  const std::string encrypted_bf_file = "test_data_bf.enc";
  const std::string decrypted_file = "test_data_decrypted.txt";

  int failures = 0;

  // Create test file
  printf("--- Creating test file ---\n");
  const char* test_content = "This is test file content.\nIt has multiple lines.\nAnd should encrypt/decrypt correctly!\n";
  if (!write_file(test_file, reinterpret_cast<const unsigned char*>(test_content), strlen(test_content))) {
    printf("✗ Failed to create test file!\n");
    return 1;
  }
  printf("✓ Created test file: %s (%zu bytes)\n", test_file.c_str(), strlen(test_content));

  try {
    // Read test file
    std::vector<unsigned char> file_data = read_file(test_file);
    printf("✓ Read test file: %zu bytes\n\n", file_data.size());

    // Test 1: AES file encryption
    printf("--- Test 1: AES File Encryption ---\n");
    std::vector<unsigned char> encrypted_aes(file_data.size() + 1024); // Extra space for header + padding
    size_t encrypted_aes_len;

    if (encrypt_with_password_AES(password, file_data.data(), file_data.size(),
                                  encrypted_aes.data(), &encrypted_aes_len) > 0) {
      printf("✓ AES encryption succeeded (%zu bytes)\n", encrypted_aes_len);

      // Write encrypted file
      if (write_file(encrypted_aes_file, encrypted_aes.data(), encrypted_aes_len)) {
        printf("✓ Wrote encrypted file: %s\n", encrypted_aes_file.c_str());

        // Read encrypted file and decrypt
        std::vector<unsigned char> encrypted_read = read_file(encrypted_aes_file);
        std::vector<unsigned char> decrypted(file_data.size() + 100);
        size_t decrypted_len;

        if (decrypt_with_password(password, encrypted_read.data(), encrypted_read.size(),
                                  decrypted.data(), &decrypted_len) > 0) {
          printf("✓ AES decryption succeeded (%zu bytes)\n", decrypted_len);

          // Write decrypted file
          if (write_file(decrypted_file, decrypted.data(), decrypted_len)) {
            printf("✓ Wrote decrypted file: %s\n", decrypted_file.c_str());

            // Verify content matches
            if (decrypted_len == file_data.size() &&
                memcmp(file_data.data(), decrypted.data(), decrypted_len) == 0) {
              printf("✓ File content matches after encryption/decryption!\n");
            } else {
              printf("✗ ERROR: File content doesn't match!\n");
              failures++;
            }
          }
        } else {
          printf("✗ AES file decryption failed!\n");
          failures++;
        }
      } else {
        printf("✗ Failed to write encrypted file!\n");
        failures++;
      }
    } else {
      printf("✗ AES file encryption failed!\n");
      failures++;
    }

    // Test 2: Blowfish file encryption
    printf("\n--- Test 2: Blowfish File Encryption ---\n");
    std::vector<unsigned char> encrypted_bf(file_data.size() + 1024);
    size_t encrypted_bf_len;

    if (encrypt_with_password_BF(password, file_data.data(), file_data.size(),
                                 encrypted_bf.data(), &encrypted_bf_len) > 0) {
      printf("✓ Blowfish encryption succeeded (%zu bytes)\n", encrypted_bf_len);

      // Write encrypted file
      if (write_file(encrypted_bf_file, encrypted_bf.data(), encrypted_bf_len)) {
        printf("✓ Wrote encrypted file: %s\n", encrypted_bf_file.c_str());

        // Read encrypted file and decrypt
        std::vector<unsigned char> encrypted_read = read_file(encrypted_bf_file);
        std::vector<unsigned char> decrypted(file_data.size() + 100);
        size_t decrypted_len;

        if (decrypt_with_password(password, encrypted_read.data(), encrypted_read.size(),
                                  decrypted.data(), &decrypted_len) > 0) {
          printf("✓ Blowfish decryption succeeded (%zu bytes)\n", decrypted_len);

          // Verify content matches
          if (decrypted_len == file_data.size() &&
              memcmp(file_data.data(), decrypted.data(), decrypted_len) == 0) {
            printf("✓ File content matches after encryption/decryption!\n");
          } else {
            printf("✗ ERROR: File content doesn't match!\n");
            failures++;
          }
        } else {
          printf("✗ Blowfish file decryption failed!\n");
          failures++;
        }
      } else {
        printf("✗ Failed to write encrypted file!\n");
        failures++;
      }
    } else {
      printf("✗ Blowfish file encryption failed!\n");
      failures++;
    }

  } catch (const std::exception& e) {
    printf("✗ Exception: %s\n", e.what());
    failures++;
  }

  // Cleanup
  remove(test_file.c_str());
  remove(encrypted_aes_file.c_str());
  remove(encrypted_bf_file.c_str());
  remove(decrypted_file.c_str());

  return failures;
}

// Test hasher module
int test_hasher() {
  printf("\n\n=== HASHER MODULE TESTS ===\n\n");

  int failures = 0;

  // Test 1: SHA256 string hashing
  printf("--- Test 1: SHA256 String Hashing ---\n");
  std::string test_string = "Hello, World!";
  std::string sha256_hash = sha256_string(test_string);
  printf("Input: \"%s\"\n", test_string.c_str());
  printf("SHA256: %s\n", sha256_hash.c_str());

  // Verify hash length (SHA256 = 64 hex characters)
  if (sha256_hash.length() == 64) {
    printf("✓ SHA256 hash length correct (64 chars)\n");
  } else {
    printf("✗ ERROR: SHA256 hash length incorrect (%zu chars)\n", sha256_hash.length());
    failures++;
  }

  // Test consistency
  std::string sha256_hash2 = sha256_string(test_string);
  if (sha256_hash == sha256_hash2) {
    printf("✓ SHA256 hash is consistent\n");
  } else {
    printf("✗ ERROR: SHA256 hash is not consistent!\n");
    failures++;
  }

  // Test 2: MD5 string hashing
  printf("\n--- Test 2: MD5 String Hashing ---\n");
  std::string md5_hash = md5_string(test_string);
  printf("Input: \"%s\"\n", test_string.c_str());
  printf("MD5: %s\n", md5_hash.c_str());

  // Verify hash length (MD5 = 32 hex characters)
  if (md5_hash.length() == 32) {
    printf("✓ MD5 hash length correct (32 chars)\n");
  } else {
    printf("✗ ERROR: MD5 hash length incorrect (%zu chars)\n", md5_hash.length());
    failures++;
  }

  // Test 3: SHA256 data hashing (raw bytes)
  printf("\n--- Test 3: SHA256 Data Hashing ---\n");
  unsigned char data[] = {0x01, 0x02, 0x03, 0x04, 0x05};
  std::string data_hash = sha256_data(data, sizeof(data));
  printf("Data: 0x01 0x02 0x03 0x04 0x05\n");
  printf("SHA256: %s\n", data_hash.c_str());
  if (data_hash.length() == 64) {
    printf("✓ SHA256 data hash length correct\n");
  } else {
    failures++;
  }

  // Test 4: MD5 data hashing
  printf("\n--- Test 4: MD5 Data Hashing ---\n");
  std::string md5_data_hash = md5_data(data, sizeof(data));
  printf("Data: 0x01 0x02 0x03 0x04 0x05\n");
  printf("MD5: %s\n", md5_data_hash.c_str());
  if (md5_data_hash.length() == 32) {
    printf("✓ MD5 data hash length correct\n");
  } else {
    failures++;
  }

  // Test 5: SHA256 raw output
  printf("\n--- Test 5: SHA256 Raw Output ---\n");
  std::vector<unsigned char> raw_hash = sha256_raw(data, sizeof(data));
  printf("Raw hash size: %zu bytes (should be 32)\n", raw_hash.size());
  if (raw_hash.size() == 32) {
    printf("✓ SHA256 raw output size correct\n");
  } else {
    printf("✗ ERROR: SHA256 raw output size incorrect!\n");
    failures++;
  }

  // Test 6: MD5 raw output
  printf("\n--- Test 6: MD5 Raw Output ---\n");
  std::vector<unsigned char> md5_raw_hash = md5_raw(data, sizeof(data));
  printf("Raw hash size: %zu bytes (should be 16)\n", md5_raw_hash.size());
  if (md5_raw_hash.size() == 16) {
    printf("✓ MD5 raw output size correct\n");
  } else {
    printf("✗ ERROR: MD5 raw output size incorrect!\n");
    failures++;
  }

  // Test 7: File hashing
  printf("\n--- Test 7: File Hashing ---\n");
  const std::string hash_test_file = "hash_test.txt";
  const char* file_content = "This is test content for file hashing.\nLine 2.\nLine 3.\n";

  if (write_file(hash_test_file, reinterpret_cast<const unsigned char*>(file_content), strlen(file_content))) {
    printf("✓ Created test file\n");

    try {
      // SHA256 file hash
      std::string file_sha256 = sha256_file(hash_test_file);
      printf("SHA256(file): %s\n", file_sha256.c_str());
      if (file_sha256.length() == 64) {
        printf("✓ SHA256 file hash length correct\n");
      } else {
        failures++;
      }

      // MD5 file hash
      std::string file_md5 = md5_file(hash_test_file);
      printf("MD5(file): %s\n", file_md5.c_str());
      if (file_md5.length() == 32) {
        printf("✓ MD5 file hash length correct\n");
      } else {
        failures++;
      }

      // Verify file hash matches data hash
      std::string data_sha256 = sha256_data(reinterpret_cast<const unsigned char*>(file_content), strlen(file_content));
      if (file_sha256 == data_sha256) {
        printf("✓ File hash matches data hash\n");
      } else {
        printf("✗ ERROR: File hash doesn't match data hash!\n");
        failures++;
      }

    } catch (const std::exception& e) {
      printf("✗ Exception during file hashing: %s\n", e.what());
      failures++;
    }

    remove(hash_test_file.c_str());
  } else {
    printf("✗ Failed to create test file for hashing\n");
    failures++;
  }

  // Test 8: Empty string hashing
  printf("\n--- Test 8: Empty String Hashing ---\n");
  std::string empty = "";
  std::string empty_sha256 = sha256_string(empty);
  std::string empty_md5 = md5_string(empty);
  printf("SHA256(\"\"): %s\n", empty_sha256.c_str());
  printf("MD5(\"\"): %s\n", empty_md5.c_str());
  if (empty_sha256.length() == 64 && empty_md5.length() == 32) {
    printf("✓ Empty string hashing works correctly\n");
  } else {
    failures++;
  }

  // Test 9: Large data hashing
  printf("\n--- Test 9: Large Data Hashing ---\n");
  std::string large_data(10000, 'A'); // 10KB of 'A's
  std::string large_sha256 = sha256_string(large_data);
  std::string large_md5 = md5_string(large_data);
  printf("Large data size: %zu bytes\n", large_data.size());
  printf("SHA256: %s\n", large_sha256.c_str());
  printf("MD5: %s\n", large_md5.c_str());
  if (large_sha256.length() == 64 && large_md5.length() == 32) {
    printf("✓ Large data hashing works correctly\n");
  } else {
    failures++;
  }

  return failures;
}

int run_encryption_tests() {
  printf("\n");
  printf("╔════════════════════════════════════════════════════════════╗\n");
  printf("║         COMPREHENSIVE ENCRYPTION & HASHING TEST SUITE      ║\n");
  printf("╚════════════════════════════════════════════════════════════╝\n");

  int total_failures = 0;

  // Run all test suites
  total_failures += test_string_encryption();
  total_failures += test_file_encryption();
  total_failures += test_hasher();

  // Summary
  printf("\n\n");
  printf("╔════════════════════════════════════════════════════════════╗\n");
  printf("║                      TEST SUMMARY                          ║\n");
  printf("╚════════════════════════════════════════════════════════════╝\n");

  if (total_failures == 0) {
    printf("\n✓✓✓ ALL TESTS PASSED! ✓✓✓\n\n");
    return 0;
  } else {
    printf("\n✗✗✗ %d TEST(S) FAILED! ✗✗✗\n\n", total_failures);
    return 1;
  }
}
