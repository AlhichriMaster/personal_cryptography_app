#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <cstddef>

// Low-level encryption/decryption functions
// crypt: 1 = encrypt, 0 = decrypt
int do_crypt_AES(const unsigned char *key, const unsigned char *iv,
                 const unsigned char *msg, size_t msg_len,
                 unsigned char *out, int crypt);

int do_crypt_BF(const unsigned char *key, const unsigned char *iv,
                const unsigned char *msg, size_t msg_len,
                unsigned char *out, int crypt, int *out_len);

// Utility functions
bool generate_random_bytes(unsigned char *buf, size_t len);

bool derive_key_from_password(const char *password,
                              const unsigned char *salt, size_t salt_len,
                              unsigned char *key, size_t key_len);

// High-level password-based encryption (auto-detects algorithm on decrypt)
// Output format: [algo_id(1)][salt(16)][iv(variable)][ciphertext(variable)]
int encrypt_with_password(const char *password,
                         const unsigned char *plaintext, size_t plaintext_len,
                         unsigned char *output, size_t *output_len);

int decrypt_with_password(const char *password,
                         const unsigned char *input, size_t input_len,
                         unsigned char *plaintext, size_t *plaintext_len);

// Algorithm-specific encryption functions
int encrypt_with_password_AES(const char *password,
                              const unsigned char *plaintext, size_t plaintext_len,
                              unsigned char *output, size_t *output_len);

int encrypt_with_password_BF(const char *password,
                             const unsigned char *plaintext, size_t plaintext_len,
                             unsigned char *output, size_t *output_len);

#endif // ENCRYPTION_H
