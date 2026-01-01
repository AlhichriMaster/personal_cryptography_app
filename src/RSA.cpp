#include "../include/RSA.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <cstring>
#include <iostream>
#include <fstream>
#include <sstream>
#include <stdexcept>
#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

/**
 * @brief Get OpenSSL error string
 * @return Last OpenSSL error as a string
 */
static std::string get_openssl_error() {
    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char *buf = nullptr;
    size_t len = BIO_get_mem_data(bio, &buf);
    std::string ret(buf, len);
    BIO_free(bio);
    return ret;
}


/**
 * @brief Base64 encode binary data
 * @param data Input binary data
 * @param len Length of input data
 * @return Base64 encoded string
 */
static std::string base64_encode(const unsigned char* data, size_t len) {
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // No newlines
    BIO_write(bio, data, len);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &buffer_ptr);

    std::string result(buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(bio);

    return result;
}


/**
 * @brief Base64 decode string to binary data
 * @param encoded Base64 encoded string
 * @return Vector of decoded bytes
 */
static std::vector<unsigned char> base64_decode(const std::string& encoded) {
    BIO *bio, *b64;
    int decode_len = encoded.length();
    std::vector<unsigned char> buffer(decode_len);

    bio = BIO_new_mem_buf(encoded.data(), decode_len);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int len = BIO_read(bio, buffer.data(), decode_len);
    BIO_free_all(bio);

    buffer.resize(len);
    return buffer;
}



// ============================================================================
// Key Generation
// ============================================================================

/**
 * @brief Generate RSA key pair
 *
 * This function generates an RSA key pair with the specified bit length.
 * The keys are returned in PEM format for easy storage and transmission.
 *
 * @param bits Key size in bits (2048 or 4096 recommended)
 * @return RSAKeyPair structure containing public and private keys in PEM format
 *
 * @throws std::runtime_error if key generation fails
 *
 * Example usage:
 * @code
 * RSAKeyPair keys = generate_rsa_keypair(2048);
 * std::cout << "Public Key:\n" << keys.public_key_pem << std::endl;
 * save_private_key("mykey.pem", keys.private_key_pem);
 * @endcode
 */
RSAKeyPair generate_rsa_keypair(int bits){
  /* Create the context for generating the parameters */
  RSAKeyPair generated_keys;

  EVP_PKEY_CTX* ctx = nullptr;
  EVP_PKEY* pkey = nullptr;
  BIO* pub_bio = nullptr;
  BIO* priv_bio = nullptr;

  try {
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);

    //initialize the context
    if(!ctx) {
      throw std::runtime_error("Failed to create RSA context: " + get_openssl_error());
    }

    //initialize key generation
    if(EVP_PKEY_keygen_init(ctx) <= 0) {
      throw std::runtime_error("Failed to initialize keygen: " + get_openssl_error());
    }

    //set the key size
    if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0){
      throw std::runtime_error("Failed to set key size: " + get_openssl_error());
    }

    //Generate the keys:
    if(EVP_PKEY_keygen(ctx, &pkey) <= 0) {
      throw std::runtime_error("Failed to generate key: " + get_openssl_error());
    }

    pub_bio = BIO_new(BIO_s_mem());
    if(!PEM_write_bio_PUBKEY(pub_bio, pkey)) {
      throw std::runtime_error("Failed to write public key: " + get_openssl_error());
    }

    BUF_MEM *pub_mem = nullptr;
    BIO_get_mem_ptr(pub_bio, &pub_mem);
    generated_keys.public_key_pem = std::string(pub_mem->data, pub_mem->length);


    priv_bio = BIO_new(BIO_s_mem());
    if(!PEM_write_bio_PrivateKey(priv_bio, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
      throw std::runtime_error("Failed to write private key: " + get_openssl_error());
    }

    BUF_MEM *priv_mem = nullptr;
    BIO_get_mem_ptr(priv_bio, &priv_mem);
    generated_keys.private_key_pem = std::string(priv_mem->data, priv_mem->length);


  } catch (...){
    if(pub_bio) BIO_free(pub_bio);
    if(priv_bio) BIO_free(priv_bio);
    if(pkey) EVP_PKEY_free(pkey);
    if(ctx) EVP_PKEY_CTX_free(ctx);
    throw;
  }

  //Cleanup
  BIO_free(pub_bio);
  BIO_free(priv_bio);
  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(ctx);

  std::cout << "RSA key pair generated successfully (" << bits << " bits)\n";
  return generated_keys;
}


// ============================================================================
// Key File Operations
// ============================================================================

/**
 * @brief Save public key to file
 * @param filepath Path to output file
 * @param pem Public key in PEM format
 * @return true if successful, false otherwise
 */
bool save_public_key(const std::string& filepath, const std::string& pem) {
    std::ofstream file(filepath);
    if (!file) {
        std::cerr << "Error: Cannot open file for writing: " << filepath << std::endl;
        return false;
    }

    file << pem;
    file.close();

    if (file.good()) {
        std::cout << "✓ Public key saved to: " << filepath << std::endl;
        return true;
    }

    return false;
}


/**
 * @brief Save private key to file with restricted permissions
 * @param filepath Path to output file
 * @param pem Private key in PEM format
 * @return true if successful, false otherwise
 */
bool save_private_key(const std::string& filepath, const std::string& pem) {
    std::ofstream file(filepath);
    if (!file) {
        std::cerr << "Error: Cannot open file for writing: " << filepath << std::endl;
        return false;
    }

    file << pem;
    file.close();

    if (file.good()) {
        // Set file permissions to 0600 (owner read/write only) on Unix systems
        #ifndef _WIN32
        chmod(filepath.c_str(), S_IRUSR | S_IWUSR);
        #endif

        std::cout << "✓ Private key saved to: " << filepath << std::endl;
        std::cout << "  (File permissions set to owner read/write only)" << std::endl;
        return true;
    }

    return false;
}



/**
 * @brief Load public key from file
 * @param filepath Path to key file
 * @return Public key in PEM format
 * @throws std::runtime_error if file cannot be read
 */
std::string load_public_key(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file) {
        throw std::runtime_error("Cannot open public key file: " + filepath);
    }

    std::stringstream buffer;
    buffer << file.rdbuf();

    std::string pem = buffer.str();
    if (pem.empty()) {
        throw std::runtime_error("Public key file is empty: " + filepath);
    }

    std::cout << "✓ Public key loaded from: " << filepath << std::endl;
    return pem;
}


/**
 * @brief Load private key from file
 * @param filepath Path to key file
 * @return Private key in PEM format
 * @throws std::runtime_error if file cannot be read
 */
std::string load_private_key(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file) {
        throw std::runtime_error("Cannot open private key file: " + filepath);
    }

    std::stringstream buffer;
    buffer << file.rdbuf();

    std::string pem = buffer.str();
    if (pem.empty()) {
        throw std::runtime_error("Private key file is empty: " + filepath);
    }

    std::cout << "✓ Private key loaded from: " << filepath << std::endl;
    return pem;
}



// ============================================================================
// Encryption / Decryption
// ============================================================================

/**
 * @brief Encrypt data using RSA public key
 *
 * This function encrypts data using the RSA public key with OAEP padding.
 * The encrypted data is returned as a base64-encoded string.
 *
 * IMPORTANT: RSA can only encrypt data smaller than the key size.
 * For 2048-bit keys, maximum plaintext is ~245 bytes (with OAEP padding).
 * For larger data, use hybrid encryption (RSA + AES).
 *
 * @param public_key_pem Public key in PEM format
 * @param data Pointer to data to encrypt
 * @param len Length of data in bytes
 * @return Base64-encoded ciphertext
 *
 * @throws std::runtime_error if encryption fails or data is too large
 */
std::string rsa_encrypt_public(const std::string& public_key_pem,
                                const unsigned char* data, size_t len) {

  EVP_PKEY *pkey = nullptr;
  EVP_PKEY_CTX *ctx = nullptr;
  BIO *bio = nullptr;

  try {
    //Load public key
    bio = BIO_new_mem_buf(public_key_pem.data(), public_key_pem.length());
    if(!bio) {
      throw std::runtime_error("Failed to create BIO: " + get_openssl_error());
    }

    //read public key and set it to pkey
    pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    if(!pkey) {
      throw std::runtime_error("Failed to read public key: " + get_openssl_error());
    }

    //init the encryption context
    ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
      throw std::runtime_error("Failed to create context: " + get_openssl_error());
    }

    //initialize the encryption process
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
      throw std::runtime_error("Failed to initialize encryption: " + get_openssl_error());
    }

    //set padding to OAEP
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
      throw std::runtime_error("Failed to set padding: " + get_openssl_error());
    }

    // Determine buffer length
    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, data, len) <= 0) {
      throw std::runtime_error("Failed to determine output length: " + get_openssl_error());
    }

    // Allocate output buffer
    std::vector<unsigned char> encrypted(outlen);

    //perform encryption
    if (EVP_PKEY_encrypt(ctx, encrypted.data(), &outlen, data, len) <= 0) {
      throw std::runtime_error("Encryption failed: " + get_openssl_error());
    }

    encrypted.resize(outlen);

    //Cleanup
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);


    return base64_encode(encrypted.data(), encrypted.size());

  } catch(...) {
    if(ctx) EVP_PKEY_CTX_free(ctx);
    if(pkey) EVP_PKEY_free(pkey);
    if(bio) BIO_free(bio);
    throw;
  }
}



/**
 * @brief Decrypt data using RSA private key
 *
 * This function decrypts base64-encoded ciphertext using the RSA private key.
 *
 * @param private_key_pem Private key in PEM format
 * @param ciphertext_base64 Base64-encoded ciphertext
 * @return Decrypted data as vector of bytes
 *
 * @throws std::runtime_error if decryption fails
 */
std::vector<unsigned char> rsa_decrypt_private(const std::string& private_key_pem,
                                                const std::string& ciphertext_base64) {
    EVP_PKEY *pkey = nullptr;
    EVP_PKEY_CTX *ctx = nullptr;
    BIO *bio = nullptr;


    try {

      std::vector<unsigned char> ciphertext = base64_decode(ciphertext_base64);

      //Load private key
      bio = BIO_new_mem_buf(private_key_pem.data(), private_key_pem.length());
      if(!bio) {
        throw std::runtime_error("Failed to create BIO: " + get_openssl_error());
      }

      pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
      if(!pkey) {
        throw std::runtime_error("Failed to read private key: " + get_openssl_error());
      }

      ctx = EVP_PKEY_CTX_new(pkey, nullptr);
      if (!ctx) {
        throw std::runtime_error("Failed to create context" + get_openssl_error());
      }

      if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        throw std::runtime_error("Failed to initialize decryption" + get_openssl_error());
      }

      //set padding to OAEP
      if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        throw std::runtime_error("Failed to set padding: " + get_openssl_error());
      }

      size_t outlen;
      if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, ciphertext.data(), ciphertext.size()) <= 0) {
        throw std::runtime_error("Failed to determine output length" + get_openssl_error());
      }

      std::vector<unsigned char> decrypted(outlen);

      if (EVP_PKEY_decrypt(ctx, decrypted.data(), &outlen, ciphertext.data(), ciphertext.size()) <= 0) {
        throw std::runtime_error("Decryption failed: " + get_openssl_error());
      }

      decrypted.resize(outlen);

      EVP_PKEY_CTX_free(ctx);
      EVP_PKEY_free(pkey);
      BIO_free(bio);

      return decrypted;

    } catch(...) {
      if (ctx) EVP_PKEY_CTX_free(ctx);
      if (pkey) EVP_PKEY_free(pkey);
      if (bio) BIO_free(bio);
      throw;
    }
}
