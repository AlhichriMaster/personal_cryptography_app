#include "../include/Signature.h"
#include "../include/Hasher.h"  // Only needed for file reading helper
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <iostream>
#include <cstring>

//GOAL: Sign data using RSA private key

// ============================================================================
// Helper Functions
// ============================================================================

static std::string get_openssl_error() {
    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char *buf = nullptr;
    size_t len = BIO_get_mem_data(bio, &buf);
    std::string ret(buf, len);
    BIO_free(bio);
    return ret;
}

static std::string base64_encode(const unsigned char* data, size_t len) {
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data, len);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &buffer_ptr);

    std::string result(buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(bio);

    return result;
}

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
// Digital Signature Functions
// ============================================================================

/**
 * @brief Sign data using RSA private key with SHA-256
 *
 * This function creates a digital signature by:
 * 1. Hashing the data with SHA-256 (done internally by EVP_DigestSign)
 * 2. Encrypting the hash with the private key
 *
 * The EVP_DigestSign API handles both steps atomically and correctly.
 *
 * @param private_key_pem Private key in PEM format
 * @param data Pointer to data to sign
 * @param len Length of data
 * @return Base64-encoded signature
 *
 * @throws std::runtime_error if signing fails
 */
std::string sign_data(const std::string& private_key_pem,
                      const unsigned char* data, size_t len) {
  EVP_MD_CTX *md_ctx = nullptr;
  EVP_PKEY *pkey = nullptr;
  BIO *bio = nullptr;


  try {

   md_ctx = EVP_MD_CTX_new();

   if (!md_ctx) {
     throw std::runtime_error("Failed to create hashing context" + get_openssl_error());
   }

    bio = BIO_new_mem_buf(private_key_pem.data(), private_key_pem.size());
    if (!bio) {
      throw std::runtime_error("Failed to create BIO" + get_openssl_error());
    }

    pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    if (!pkey) {
      throw std::runtime_error("Failed to read private key" + get_openssl_error());
    }

    if(EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
      throw std::runtime_error("Failed to initialize signing" + get_openssl_error());
    }
    if(EVP_DigestSignUpdate(md_ctx, data, len) <= 0) {
      throw std::runtime_error("Failed to add data to sign" + get_openssl_error());
    }

    size_t sig_len = 0;
    if(EVP_DigestSignFinal(md_ctx, nullptr, &sig_len) <= 0) {
      throw std::runtime_error("Failed to generate signature" + get_openssl_error());
    }
    std::vector<unsigned char> signature(sig_len);
    if(EVP_DigestSignFinal(md_ctx, signature.data(), &sig_len) <= 0) {
      throw std::runtime_error("Failed to generate signature" + get_openssl_error());
    }

    signature.resize(sig_len);

    EVP_MD_CTX_free(md_ctx);
    BIO_free(bio);
    EVP_PKEY_free(pkey);

    return base64_encode(signature.data(), signature.size());

  } catch (...) {
    if(md_ctx) EVP_MD_CTX_free(md_ctx);
    if(bio) BIO_free(bio);
    if(pkey) EVP_PKEY_free(pkey);
    throw;
  }

}


/**
 * @brief Verify signature using RSA public key
 *
 * This function verifies a digital signature by:
 * 1. Hashing the data with SHA-256 (done internally)
 * 2. Comparing it with the decrypted signature
 *
 * @param public_key_pem Public key in PEM format
 * @param data Pointer to data that was signed
 * @param len Length of data
 * @param signature_base64 Base64-encoded signature
 * @return true if signature is valid, false otherwise
 */
bool verify_signature(const std::string& public_key_pem,
                      const unsigned char* data, size_t len,
                      const std::string& signature_base64) {

  EVP_MD_CTX *md_ctx = nullptr;
  EVP_PKEY *pkey = nullptr;
  BIO *bio = nullptr;

  try {
    std::vector<unsigned char> signature = base64_decode(signature_base64);

    bio = BIO_new_mem_buf(public_key_pem.data(), public_key_pem.length());
    if (!bio){
      throw std::runtime_error("Failed to read public key" + get_openssl_error());
    }

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
      throw std::runtime_error("Failed to create hashing context" + get_openssl_error());
    }

    pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    if (!pkey) {
      throw std::runtime_error("Failed to read private key" + get_openssl_error());
    }

    if(EVP_DigestVerifyInit(md_ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0){
      throw std::runtime_error("Failed to initialize verification" + get_openssl_error());
    }

    if(EVP_DigestVerifyUpdate(md_ctx, data, len) <= 0) {
      throw std::runtime_error("Failed to add data to sign" + get_openssl_error());
    }

    int verify_result = EVP_DigestVerifyFinal(md_ctx, signature.data(), signature.size());

    EVP_MD_CTX_free(md_ctx);
    BIO_free(bio);
    EVP_PKEY_free(pkey);

    if (verify_result < 0) {
      throw std::runtime_error("Verification error: " + get_openssl_error());
    }

    return (verify_result == 1);

  } catch (...) {
    if(md_ctx) EVP_MD_CTX_free(md_ctx);
    if(bio) BIO_free(bio);
    if(pkey) EVP_PKEY_free(pkey);
    throw;
  }
}


// ============================================================================
// File Signature Functions
// ============================================================================

/**
 * @brief Sign a file
 *
 * Reads the file in chunks and signs it using EVP_DigestSignUpdate
 * to handle large files efficiently.
 *
 * @param private_key_pem Private key in PEM format
 * @param filepath Path to file to sign
 * @return Base64-encoded signature
 */
std::string sign_file(const std::string& private_key_pem,
                      const std::string& filepath) {
  EVP_MD_CTX* md_ctx = nullptr;
  EVP_PKEY* pkey = nullptr;
  BIO* bio = nullptr;
  std::ifstream file;


  try {

    bio = BIO_new_mem_buf(private_key_pem.data(), private_key_pem.size());
    if (!bio){
      throw std::runtime_error("Could not load private key" + get_openssl_error());
    }

    pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    if (!pkey) {
      throw std::runtime_error("Failed to read private key" + get_openssl_error());
    }

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
      throw std::runtime_error("Failed to create hashing context" + get_openssl_error());
    }

    if(EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0){
      throw std::runtime_error("Could not initialize sign function" + get_openssl_error());
    }

    file.open(filepath, std::ios::binary);
    if (!file){
      throw std::runtime_error("Could not read provided file" + get_openssl_error());
    }

    const size_t CHUNK_SIZE = 4096;
    char buffer[CHUNK_SIZE];

    while (file.read(buffer, CHUNK_SIZE) || file.gcount() > 0){
      if(EVP_DigestSignUpdate(md_ctx, buffer, file.gcount()) <= 0){
        throw std::runtime_error("Failed to update digest" + get_openssl_error());
      }
    }

    file.close();

    size_t sig_len = 0;
    EVP_DigestSignFinal(md_ctx, nullptr, &sig_len);

    std::vector<unsigned char> signature(sig_len);
    if(EVP_DigestSignFinal(md_ctx, signature.data(), &sig_len) <= 0){
      throw std::runtime_error("Failed to generate signature" + get_openssl_error());
    }


    EVP_MD_CTX_free(md_ctx);
    BIO_free(bio);
    EVP_PKEY_free(pkey);

    signature.resize(sig_len);
    return base64_encode(signature.data(), signature.size());

  } catch (...) {
    if(md_ctx) EVP_MD_CTX_free(md_ctx);
    if(bio) BIO_free(bio);
    if(pkey) EVP_PKEY_free(pkey);
    throw;
  }

}


/**
 * @brief Verify file signature
 *
 * @param public_key_pem Public key in PEM format
 * @param filepath Path to file to verify
 * @param signature_base64 Base64-encoded signature
 * @return true if signature is valid
 */
bool verify_file_signature(const std::string& public_key_pem,
                           const std::string& filepath,
                           const std::string& signature_base64){


  EVP_MD_CTX* md_ctx = nullptr;
  EVP_PKEY* pkey = nullptr;
  BIO* bio = nullptr;
  std::ifstream file;


  try {

    std::vector<unsigned char> signature = base64_decode(signature_base64);

    bio = BIO_new_mem_buf(public_key_pem.data(), public_key_pem.size());
    if (!bio){
      throw std::runtime_error("Could not load public key" + get_openssl_error());
    }

    pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    if (!pkey) {
      throw std::runtime_error("Failed to read public key" + get_openssl_error());
    }

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
      throw std::runtime_error("Failed to create hashing context" + get_openssl_error());
    }

   if(EVP_DigestVerifyInit(md_ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0){
     throw std::runtime_error("Failed to initialize verification" + get_openssl_error());
   }

   file.open(filepath, std::ios::binary);
   if (!file){
     throw std::runtime_error("Failed to load up the file" + get_openssl_error());
   }

   const size_t CHUNK_SIZE = 4096;
   char buffer[CHUNK_SIZE];

   while (file.read(buffer, CHUNK_SIZE) || file.gcount() > 0){
     if(EVP_DigestVerifyUpdate(md_ctx, buffer, file.gcount()) <= 0){
       throw std::runtime_error("Failed to update verification digest" + get_openssl_error());
     }
   }

   file.close();

   int verify_result = EVP_DigestVerifyFinal(md_ctx, signature.data(), signature.size());

    EVP_MD_CTX_free(md_ctx);
    BIO_free(bio);
    EVP_PKEY_free(pkey);


    if(verify_result < 0){
      throw std::runtime_error("Verification error: " + get_openssl_error());
    }

    return (verify_result == 1);


  } catch (...) {
    if(md_ctx) EVP_MD_CTX_free(md_ctx);
    if(bio) BIO_free(bio);
    if(pkey) EVP_PKEY_free(pkey);
    throw;
  }

}

/**
 * @brief Create detached signature file (.sig)
 *
 * Creates a signature file in the format:
 * SIGNATURE-V1
 * <base64-signature>
 *
 * @param private_key_pem Private key in PEM format
 * @param filepath Path to file to sign
 * @param sig_filepath Path to output .sig file
 * @return true if successful
 */
bool create_signature_file(const std::string& private_key_pem,
                           const std::string& filepath,
                           const std::string& sig_filepath) {
    try {
        // Sign the file
        std::string signature = sign_file(private_key_pem, filepath);

        // Write signature to file
        std::ofstream sig_file(sig_filepath);
        if (!sig_file) {
            throw std::runtime_error("Cannot create signature file: " + sig_filepath);
        }

        sig_file << "SIGNATURE-V1\n";
        sig_file << signature << "\n";
        sig_file.close();

        std::cout << "✓ Signature file created: " << sig_filepath << std::endl;
        return true;

    } catch (const std::exception& e) {
        std::cerr << "Error creating signature file: " << e.what() << std::endl;
        return false;
    }
}

/**
 * @brief Verify using detached signature file
 *
 * @param public_key_pem Public key in PEM format
 * @param filepath Path to file to verify
 * @param sig_filepath Path to .sig file
 * @return true if signature is valid
 */
bool verify_signature_file(const std::string& public_key_pem,
                           const std::string& filepath,
                           const std::string& sig_filepath) {
    try {
        // Read signature file
        std::ifstream sig_file(sig_filepath);
        if (!sig_file) {
            throw std::runtime_error("Cannot open signature file: " + sig_filepath);
        }

        std::string header;
        std::getline(sig_file, header);

        if (header != "SIGNATURE-V1") {
            throw std::runtime_error("Invalid signature file format");
        }

        std::string signature;
        std::getline(sig_file, signature);
        sig_file.close();

        // Verify
        bool valid = verify_file_signature(public_key_pem, filepath, signature);

        if (valid) {
            std::cout << "✓ Signature is VALID for: " << filepath << std::endl;
        } else {
            std::cout << "✗ Signature is INVALID for: " << filepath << std::endl;
        }

        return valid;

    } catch (const std::exception& e) {
        std::cerr << "Error verifying signature: " << e.what() << std::endl;
        return false;
    }
}
