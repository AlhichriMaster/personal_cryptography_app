#ifndef HASHER_H
#define HASHER_H


#include <string>
#include <vector>



//compute SHA256 hash of a string and return as hex string
std::string sha256_string(const std::string& input);


//compute SHA256 hash of binary data and return as hex string
std::string sha256_data(const unsigned char* data, size_t length);



//compute SHA256 hash of a file and return as hex string
std::string sha256_file(const std::string& filepath);


//compute SHA256 hash and return raw bytes
std::vector<unsigned char> sha256_raw(const unsigned char* data, size_t length);


// Compute MD5 hash of a string and return as hex string
std::string md5_string(const std::string& input);

// Compute MD5 hash of binary data and return as hex string
std::string md5_data(const unsigned char* data, size_t length);

// Compute MD5 hash of a file and return as hex string
std::string md5_file(const std::string& filepath);

// Compute MD5 hash and return raw bytes (16 bytes)
std::vector<unsigned char> md5_raw(const unsigned char* data, size_t length);


#endif
