#include "../include/Encryption.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/provider.h>
#include <cstring>

// Algorithm identifiers
#define ALGO_AES_256_CBC_CTS 0x01
#define ALGO_BLOWFISH_CBC    0x02

// Global providers - initialized once
static OSSL_PROVIDER *legacy_provider = NULL;
static OSSL_PROVIDER *default_provider = NULL;
static bool providers_loaded = false;

// Initialize OpenSSL providers (call this before using Blowfish)
static void init_providers() {
    if (!providers_loaded) {
        legacy_provider = OSSL_PROVIDER_load(NULL, "legacy");
        default_provider = OSSL_PROVIDER_load(NULL, "default");
        providers_loaded = true;
    }
}

int do_crypt_AES(const unsigned char *key, const unsigned char *iv,
            const unsigned char *msg, size_t msg_len, unsigned char *out, int crypt)
{
   /*
    * This assumes that key size is 32 bytes and the iv is 16 bytes.
    * For ciphertext stealing mode the length of the ciphertext "out" will be
    * the same size as the plaintext size "msg_len".
    * The "msg_len" can be any size >= 16.
    */
    int ret = 0, outlen, len;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;

    ctx = EVP_CIPHER_CTX_new();
    cipher = EVP_CIPHER_fetch(NULL, "AES-256-CBC-CTS", NULL);
    if (ctx == NULL || cipher == NULL)
        goto err;
    /*
     * The default is "CS1" so this is not really needed,
     * but would be needed to set either "CS2" or "CS3".
     */
    if (!EVP_CipherInit_ex2(ctx, cipher, key, iv, crypt, NULL))
        goto err;
    /* NOTE: CTS mode does not support multiple calls to EVP_CipherUpdate() */
    if (!EVP_CipherUpdate(ctx, out, &outlen, msg, msg_len))
        goto err;
     if (!EVP_CipherFinal_ex(ctx, out + outlen, &len))
        goto err;
    ret = 1;
err:
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}


int do_crypt_BF(const unsigned char *key, const unsigned char *iv,
            const unsigned char *msg, size_t msg_len, unsigned char *out,
            int crypt, int *out_len)
{
   /*
    * This assumes that key size is 16 bytes and the iv is 8 bytes for Blowfish.
    * Blowfish uses 64-bit (8-byte) blocks with PKCS7 padding.
    */
    int ret = 0, outlen, len;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;

    // Ensure legacy provider is loaded for Blowfish
    init_providers();

    ctx = EVP_CIPHER_CTX_new();
    cipher = EVP_CIPHER_fetch(NULL, "BF-CBC", NULL);
    if (ctx == NULL || cipher == NULL)
        goto err;

    if (!EVP_CipherInit_ex2(ctx, cipher, key, iv, crypt, NULL))
        goto err;

    if (!EVP_CipherUpdate(ctx, out, &outlen, msg, msg_len))
        goto err;

     if (!EVP_CipherFinal_ex(ctx, out + outlen, &len))
        goto err;

    // Return actual output length (important for Blowfish with padding)
    if (out_len != NULL) {
        *out_len = outlen + len;
    }

    ret = 1;
err:
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}



bool generate_random_bytes(unsigned char *buf, size_t len){
  return RAND_bytes(buf, len) == 1;
}

//Derive a key from the password provided
bool derive_key_from_password(const char *password,
                              const unsigned char *salt, size_t salt_len,
                              unsigned char *key, size_t key_len){
  return PKCS5_PBKDF2_HMAC(password, strlen(password), salt, salt_len, 100000,
                           EVP_sha256(), key_len, key) == 1;
}


//encrypt the data with AES
int encrypt_with_password_AES(const char *password,
                              const unsigned char *plaintext, size_t plaintext_len,
                              unsigned char *output, size_t *output_len){

  unsigned char salt[16];
  unsigned char iv[16];
  unsigned char key[32];

  if( !generate_random_bytes(salt, sizeof(salt)) ){
    return -1;
  }

  if( !generate_random_bytes(iv, sizeof(iv)) ){
    return -1;
  }

  if( !derive_key_from_password(password, salt, sizeof(salt), key, sizeof(key))){
    return -1;
  }

  // Output format: [algo_id(1)][salt(16)][iv(16)][ciphertext(variable)]
  output[0] = ALGO_AES_256_CBC_CTS;
  memcpy(output + 1, salt, sizeof(salt));
  memcpy(output + 1 + sizeof(salt), iv, sizeof(iv));

  //Encrypt
  int encrypt_result = do_crypt_AES(key, iv, plaintext, plaintext_len,
                                    output + 1 + sizeof(salt) + sizeof(iv), 1);

  if ( !encrypt_result ){
    return -1;
  }

  *output_len = 1 + sizeof(salt) + sizeof(iv) + plaintext_len;

  memset(key, 0, sizeof(key));

  return *output_len;
}


//encrypt the data with Blowfish
int encrypt_with_password_BF(const char *password,
                             const unsigned char *plaintext, size_t plaintext_len,
                             unsigned char *output, size_t *output_len){

  unsigned char salt[16];
  unsigned char iv[8];  // Blowfish uses 8-byte IV
  unsigned char key[16]; // Blowfish key size (can be 4-56 bytes, using 16)

  if( !generate_random_bytes(salt, sizeof(salt)) ){
    return -1;
  }

  if( !generate_random_bytes(iv, sizeof(iv)) ){
    return -1;
  }

  if( !derive_key_from_password(password, salt, sizeof(salt), key, sizeof(key))){
    return -1;
  }

  // Output format: [algo_id(1)][salt(16)][iv(8)][ciphertext(variable)]
  output[0] = ALGO_BLOWFISH_CBC;
  memcpy(output + 1, salt, sizeof(salt));
  memcpy(output + 1 + sizeof(salt), iv, sizeof(iv));

  //Encrypt
  int actual_cipher_len = 0;
  int encrypt_result = do_crypt_BF(key, iv, plaintext, plaintext_len,
                                   output + 1 + sizeof(salt) + sizeof(iv), 1, &actual_cipher_len);

  if ( !encrypt_result ){
    return -1;
  }

  // Use actual ciphertext length (includes padding)
  *output_len = 1 + sizeof(salt) + sizeof(iv) + actual_cipher_len;

  memset(key, 0, sizeof(key));

  return *output_len;
}


//Generic encrypt function - defaults to AES
int encrypt_with_password(const char *password,
                         const unsigned char *plaintext, size_t plaintext_len,
                         unsigned char *output, size_t *output_len){
  return encrypt_with_password_AES(password, plaintext, plaintext_len, output, output_len);
}


//decrypt the data - automatically detects algorithm from header
int decrypt_with_password(const char *password,
                         const unsigned char *input, size_t input_len,
                         unsigned char *plaintext, size_t *plaintext_len){

  // Minimum: algo_id(1) + salt(16) + iv(8 for BF or 16 for AES) + data
  if (input_len < 25){
    return -1;
  }

  // Read algorithm identifier
  unsigned char algo_id = input[0];

  unsigned char salt[16];
  unsigned char iv[16];  // Max IV size
  unsigned char key[32]; // Max key size

  size_t header_offset;
  size_t iv_size;
  size_t key_size;

  // Determine algorithm-specific parameters
  switch(algo_id) {
    case ALGO_AES_256_CBC_CTS:
      iv_size = 16;
      key_size = 32;
      header_offset = 1 + 16 + 16; // algo_id + salt + iv
      break;

    case ALGO_BLOWFISH_CBC:
      iv_size = 8;
      key_size = 16;
      header_offset = 1 + 16 + 8; // algo_id + salt + iv
      break;

    default:
      // Unknown algorithm
      return -1;
  }

  // Check if input is long enough
  if (input_len < header_offset) {
    return -1;
  }

  // Extract salt and IV
  memcpy(salt, input + 1, 16);
  memcpy(iv, input + 1 + 16, iv_size);

  // Derive key
  if( !derive_key_from_password(password, salt, 16, key, key_size)){
    return -1;
  }

  size_t ciphertext_len = input_len - header_offset;
  int decrypt_result;

  // Decrypt based on algorithm
  if (algo_id == ALGO_AES_256_CBC_CTS) {
    // AES-CTS doesn't use padding, output = input length
    decrypt_result = do_crypt_AES(key, iv,
                                  input + header_offset,
                                  ciphertext_len,
                                  plaintext, 0);  // 0 = decrypt mode
    if (decrypt_result) {
      *plaintext_len = ciphertext_len;
    }
  } else if (algo_id == ALGO_BLOWFISH_CBC) {
    // Blowfish uses padding, need to get actual length
    int actual_len = 0;
    decrypt_result = do_crypt_BF(key, iv,
                                 input + header_offset,
                                 ciphertext_len,
                                 plaintext, 0, &actual_len);  // 0 = decrypt mode
    if (decrypt_result) {
      *plaintext_len = actual_len;
    }
  } else {
    decrypt_result = 0;
  }

  if(!decrypt_result){
    memset(key, 0, sizeof(key));
    return -1;
  }

  memset(key, 0, sizeof(key));
  return *plaintext_len;
}
