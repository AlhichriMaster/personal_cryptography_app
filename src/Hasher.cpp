#include "../include/Hasher.h"
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>




std::string sha256_string(const std::string& input){
  return sha256_data(reinterpret_cast<const unsigned char*>(input.c_str()), input.length());
}




std::string sha256_data(const unsigned char* data, size_t length){
  EVP_MD_CTX* context = EVP_MD_CTX_new();
  const EVP_MD *md = EVP_sha256();
  unsigned char hash[SHA256_DIGEST_LENGTH];
  unsigned int hash_len;

  EVP_DigestInit_ex(context, md, nullptr);
  EVP_DigestUpdate(context, data, length);
  EVP_DigestFinal_ex(context, hash, &hash_len);
  EVP_MD_CTX_free(context);

  //convert to hex string
  std::stringstream ss;
  for ( int i = 0; i < SHA256_DIGEST_LENGTH; ++i){
    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
  }

  return ss.str();
}




std::string sha256_file(const std::string& filepath){

  std::ifstream file(filepath, std::ios::binary);
  if ( !file ) {
    throw std::runtime_error("Cannot open file: " + filepath);
  }

  SHA256_CTX shaContext;
  SHA256_Init(&shaContext);

  char buffer[4096];
  while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0){
    SHA256_Update(&shaContext, buffer, file.gcount());
  }

  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_Final(hash, &shaContext);

  //convert to hex string
  std::stringstream ss;
  for ( int i = 0; i < SHA256_DIGEST_LENGTH; ++i){
    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
  }

  return ss.str();
}




std::vector<unsigned char> sha256_raw(const unsigned char* data, size_t length){
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(data, length, hash);

  return std::vector<unsigned char>(hash, hash + SHA256_DIGEST_LENGTH);
}




std::string md5_string(const std::string& input) {
    return md5_data(reinterpret_cast<const unsigned char*>(input.c_str()),
                    input.length());
}

std::string md5_data(const unsigned char* data, size_t length) {
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_md5();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    EVP_DigestInit_ex(context, md, nullptr);
    EVP_DigestUpdate(context, data, length);
    EVP_DigestFinal_ex(context, hash, &hash_len);
    EVP_MD_CTX_free(context);

    // Convert to hex string
    std::stringstream ss;
    for (unsigned int i = 0; i < hash_len; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(hash[i]);
    }
    return ss.str();
}


std::string md5_file(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + filepath);
    }

    MD5_CTX md5Context;
    MD5_Init(&md5Context);

    char buffer[4096];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        MD5_Update(&md5Context, buffer, file.gcount());
    }

    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5_Final(hash, &md5Context);

    // Convert to hex string
    std::stringstream ss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(hash[i]);
    }
    return ss.str();
}

std::vector<unsigned char> md5_raw(const unsigned char* data, size_t length) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5(data, length, hash);
    return std::vector<unsigned char>(hash, hash + MD5_DIGEST_LENGTH);
}
