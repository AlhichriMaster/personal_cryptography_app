#ifndef SIGNATURE_H_
#define SIGNATURE_H_

#include <string>
#include <vector>


//sign the data with a private key
std::string sign_data(const std::string& private_key_pem,
                      const unsigned char* data, size_t len);


//Verify signature with public key
bool verify_signature(const std::string& public_key_pem,
                      const unsigned char* data, size_t len,
                      const std::string& signature_base64);


//sign a file
std::string sign_file(const std::string& private_key_pem,
                      const std::string& filepath);


//Verify file signature
bool verify_file_signature(const std::string& public_key_pem,
                           const std::string& filepath,
                           const std::string& signature_base64);


//Create detached signature file (.sig)
bool create_signature_file(const std::string& private_key_pem,
                           const std::string& filepath,
                           const std::string& sig_filepath);


//Verify using detached sig file
bool verify_signature_file(const std::string& public_key_pem,
                           const std::string& filepath,
                           const std::string& sig_filepath);




#endif // SIGNATURE_H_
