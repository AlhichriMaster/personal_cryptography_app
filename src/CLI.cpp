#include "../include/CLI.h"
#include "../include/Hasher.h"
#include "../include/Encryption.h"
#include "../include/RSA.h"
#include "../include/Signature.h"
#include <iostream>
#include <fstream>
#include <cstring>



CommandLineParser::CommandLineParser(int argc, char* argv[]) {
  //store all arguments for debugging
  for (int i =0; i < argc; ++i) {
    args.push_back(argv[i]);
  }

  //First argument after program name is the command
  if (argc > 1) {
    command = argv[1];
  }

  //Parse remaining arguments as option pairs
  for (int i = 2; i < argc; i++) {
    std::string arg = argv[i];

    //Check if this is an option key (starts with -)
    if(arg[0] == '-' && i + 1 < argc) {
      std::string key = arg;
      std::string value = argv[i + 1];

      // Store the option
      options[key] = value;

      // Skip the next argument
      i++;
    } else if (arg[0] == '-') {
      // Flag without value
      options[arg] = "";
    }
  }
}


std::string CommandLineParser::getOption(const std::string& key,
                                         const std::string& default_val) const {
  auto it = options.find(key);
  if (it != options.end()) {
    return it->second;
  }
  return default_val;
}


bool CommandLineParser::hasOption(const std::seting& key) const {
  return options.find(key) != options.end();
}

/**
 * @brief Print general usage information
 */
void CommandLineParser::printUsage() const {
    std::cout << "\n";
    std::cout << "╔════════════════════════════════════════════════════════════╗\n";
    std::cout << "║           CRYPTOGRAPHY APPLICATION v1.0                    ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════╝\n";
    std::cout << "\n";
    std::cout << "Usage: crypto [COMMAND] [OPTIONS]\n";
    std::cout << "\n";
    std::cout << "Available Commands:\n";
    std::cout << "  hash        Hash data using SHA-256 or MD5\n";
    std::cout << "  encrypt     Encrypt files or data\n";
    std::cout << "  decrypt     Decrypt files or data\n";
    std::cout << "  keygen      Generate RSA key pairs\n";
    std::cout << "  sign        Create digital signatures\n";
    std::cout << "  verify      Verify digital signatures\n";
    std::cout << "  help        Show this help message\n";
    std::cout << "\n";
    std::cout << "For detailed help on a command, use:\n";
    std::cout << "  crypto help [COMMAND]\n";
    std::cout << "\n";
    std::cout << "Examples:\n";
    std::cout << "  crypto hash -a sha256 -s \"Hello World\"\n";
    std::cout << "  crypto encrypt -a aes -f secret.txt -p mypassword\n";
    std::cout << "  crypto keygen -b 2048 -o mykey\n";
    std::cout << "\n";
}

/**
 * @brief Print detailed help for a specific command
 */
void CommandLineParser::printCommandHelp(const std::string& cmd) const {
    if (cmd == "hash") {
        std::cout << "\n";
        std::cout << "HASH COMMAND - Calculate cryptographic hashes\n";
        std::cout << "═══════════════════════════════════════════════\n\n";
        std::cout << "Usage: crypto hash [OPTIONS]\n\n";
        std::cout << "Options:\n";
        std::cout << "  -a <algorithm>  Hash algorithm (sha256 or md5) [default: sha256]\n";
        std::cout << "  -f <file>       File to hash\n";
        std::cout << "  -s <string>     String to hash\n";
        std::cout << "\n";
        std::cout << "Note: Must specify either -f or -s (not both)\n";
        std::cout << "\n";
        std::cout << "Examples:\n";
        std::cout << "  crypto hash -a sha256 -s \"Hello World\"\n";
        std::cout << "  crypto hash -a md5 -f document.pdf\n";
        std::cout << "  crypto hash -f image.jpg          # defaults to sha256\n";
        std::cout << "\n";

    } else if (cmd == "encrypt") {
        std::cout << "\n";
        std::cout << "ENCRYPT COMMAND - Encrypt files or data\n";
        std::cout << "════════════════════════════════════════\n\n";
        std::cout << "Usage: crypto encrypt [OPTIONS]\n\n";
        std::cout << "Options:\n";
        std::cout << "  -a <algorithm>  Encryption algorithm (aes, blowfish, or rsa) [default: aes]\n";
        std::cout << "  -f <file>       File to encrypt\n";
        std::cout << "  -o <output>     Output file [default: <input>.enc]\n";
        std::cout << "  -p <password>   Password (for aes/blowfish)\n";
        std::cout << "  -k <key_file>   Public key file (for rsa)\n";
        std::cout << "\n";
        std::cout << "Examples:\n";
        std::cout << "  crypto encrypt -a aes -f secret.txt -p mypassword\n";
        std::cout << "  crypto encrypt -a blowfish -f data.bin -p pass123 -o data.encrypted\n";
        std::cout << "  crypto encrypt -a rsa -f message.txt -k public.pem\n";
        std::cout << "\n";
        std::cout << "Note: RSA can only encrypt small files (<245 bytes for 2048-bit keys)\n";
        std::cout << "      For large files, use AES or Blowfish\n";
        std::cout << "\n";

    } else if (cmd == "decrypt") {
        std::cout << "\n";
        std::cout << "DECRYPT COMMAND - Decrypt files\n";
        std::cout << "═══════════════════════════════════\n\n";
        std::cout << "Usage: crypto decrypt [OPTIONS]\n\n";
        std::cout << "Options:\n";
        std::cout << "  -f <file>       File to decrypt (required)\n";
        std::cout << "  -o <output>     Output file [default: removes .enc extension]\n";
        std::cout << "  -p <password>   Password (for aes/blowfish)\n";
        std::cout << "  -k <key_file>   Private key file (for rsa)\n";
        std::cout << "\n";
        std::cout << "Note: Algorithm is auto-detected from file header\n";
        std::cout << "\n";
        std::cout << "Examples:\n";
        std::cout << "  crypto decrypt -f secret.txt.enc -p mypassword\n";
        std::cout << "  crypto decrypt -f data.encrypted -p pass123 -o data.bin\n";
        std::cout << "  crypto decrypt -f message.txt.enc -k private.pem\n";
        std::cout << "\n";

    } else if (cmd == "keygen") {
        std::cout << "\n";
        std::cout << "KEYGEN COMMAND - Generate RSA key pairs\n";
        std::cout << "════════════════════════════════════════\n\n";
        std::cout << "Usage: crypto keygen [OPTIONS]\n\n";
        std::cout << "Options:\n";
        std::cout << "  -b <bits>      Key size in bits (2048 or 4096) [default: 2048]\n";
        std::cout << "  -o <prefix>    Output filename prefix [default: key]\n";
        std::cout << "\n";
        std::cout << "Output files:\n";
        std::cout << "  <prefix>_public.pem   - Public key (share this)\n";
        std::cout << "  <prefix>_private.pem  - Private key (keep secret!)\n";
        std::cout << "\n";
        std::cout << "Examples:\n";
        std::cout << "  crypto keygen -b 2048 -o mykey\n";
        std::cout << "  crypto keygen -b 4096 -o secure_key\n";
        std::cout << "  crypto keygen                        # generates key_public.pem and key_private.pem\n";
        std::cout << "\n";
        std::cout << "Security Notes:\n";
        std::cout << "  - 2048-bit keys are secure for most uses\n";
        std::cout << "  - 4096-bit keys provide higher security but are slower\n";
        std::cout << "  - NEVER share your private key!\n";
        std::cout << "\n";

    } else if (cmd == "sign") {
        std::cout << "\n";
        std::cout << "SIGN COMMAND - Create digital signatures\n";
        std::cout << "═════════════════════════════════════════\n\n";
        std::cout << "Usage: crypto sign [OPTIONS]\n\n";
        std::cout << "Options:\n";
        std::cout << "  -f <file>       File to sign (required)\n";
        std::cout << "  -k <key_file>   Private key file (required)\n";
        std::cout << "  -o <sig_file>   Signature output file [default: <file>.sig]\n";
        std::cout << "\n";
        std::cout << "Examples:\n";
        std::cout << "  crypto sign -f document.pdf -k private.pem\n";
        std::cout << "  crypto sign -f contract.txt -k mykey_private.pem -o contract.signature\n";
        std::cout << "\n";
        std::cout << "What is a digital signature?\n";
        std::cout << "  A digital signature proves:\n";
        std::cout << "  1. WHO created the file (authentication)\n";
        std::cout << "  2. The file hasn't been modified (integrity)\n";
        std::cout << "  3. The signer can't deny signing it (non-repudiation)\n";
        std::cout << "\n";

    } else if (cmd == "verify") {
        std::cout << "\n";
        std::cout << "VERIFY COMMAND - Verify digital signatures\n";
        std::cout << "═══════════════════════════════════════════\n\n";
        std::cout << "Usage: crypto verify [OPTIONS]\n\n";
        std::cout << "Options:\n";
        std::cout << "  -f <file>       File to verify (required)\n";
        std::cout << "  -k <key_file>   Public key file (required)\n";
        std::cout << "  -s <sig_file>   Signature file [default: <file>.sig]\n";
        std::cout << "\n";
        std::cout << "Examples:\n";
        std::cout << "  crypto verify -f document.pdf -k public.pem\n";
        std::cout << "  crypto verify -f contract.txt -k sender_public.pem -s contract.signature\n";
        std::cout << "\n";
        std::cout << "Exit codes:\n";
        std::cout << "  0 - Signature is valid\n";
        std::cout << "  1 - Signature is invalid or error occurred\n";
        std::cout << "\n";

    } else {
        std::cout << "Unknown command: " << cmd << "\n";
        std::cout << "Try 'crypto help' for available commands.\n";
    }
}







int handle_hash_command(const CommandLineParser& parser) {
  std::string algorithm = parser.getOption("-a", "sha256");
  std::string file = parser.getOption("-f");
  std::string text = parser.getOption("-s");

  if (file.empty() && text.empty()) {
    std::cerr << "Error: Must specify either -f <file> or -s <string>\n";
    return 1;
  }

  std::string hash;

  if (!file.empty()) {
    //Hash file
    if (algorithm == "sha256") {
      hash = sha256_file(file);
    }else if (algorithm == "md5") {
      hash = md5_file(file);
    }else {
      std::cerr << "Error: Unknown algorithm: " << algorithm << "\n";
      return 1;
    }
    std::cout << algorithm << "(" << file << ") = " << hash << "\n";
  } else {
    //hash string
    if (algorithm == "sha256") {
      hash = sha256_string(text);
    } else if (algorithm == "md5") {
      hash = md5_string(text);
    }

    std::cout << algorithm << "(\"" << text << "\") = " << hash << "\n";
  }

  return 0;
}


int handle_encrypt_command(const CommandLineParser& parser){
  std::string algorithm = parser.getOption("-a", "aes");
  std::string input_file = parser.getOption("-f");
  std::string output_file = parser.getOption("-o");
  std::string password = parser.getOption("-p");
  std::string key_file = parser.getOption("-k");

  if (input_file.empty()) {
    std::cerr << "Error: Input file required (-f option)\n";
    std::cerr << "Try 'crypto help' for usage information.\n";
    return 1;
  }


  if (output_file.empty()) {
    output_file = input_file + ".enc";
  }

  //Validate algorithm
  if (algorithm != "aes" && algorithm != "blowfish" && algorithm != "rsa") {
    std:cerr << "Error: Unknown algorithm '" << algorithm << "'\n";
    std::cerr << "Supported algorithms: aes, blowfish, rsa\n";
    return 1;
  }

  //Check for required credentials
  if ((algorithm == "aes" || algorithm == "blowfish") && password.empty()) {
    std::cerr << "Error: Password required for " << algorithm << " encryption (-p option)\n";
    return 1;
  }

  if (algorithm == "rsa" && key_file.empty()) {
    std::cerr << "Error: Public key file required for RSA encryption (-k option)\n";
    return 1;
  }


  try {

    std::ifstream infile(input_file, std::ios::binary | std::ios::ate);
    if (!infile) {
      std::cerr << "Error: Cannot open input file: " << input_file << "\n";
      return 1;
    }


    std::streamsize file_size = infile.tellg();
    infile.seekg(0, std::ios::beg);

    std::vector<unsigned char> plaintext(file_size);
    if (!infile.read((char*)plaintext.data(), file_size)) {
      std::cerr << "Error: Failed to read input file\n";
      return 1;
    }
    infile.close();

    std::cout << "Read " << file_size << " bytes from " << input_file << "\n";

    std::vector<unsigned char> ciphertext;

    if (algorithm == "aes") {
      ciphertext.resize(plaintext.size() + 1024);
      size_t encrpyted_len;

      int result = encrypt_with_password_AES(password.c_str(),
                                             plaintext.data(),
                                             plaintext.size(),
                                             ciphertext.data(),
                                             &encrypted_len);

      if (result < 0) {
        std::cerr << "Error: AES encryption failed\n";
        return 1;
      }
      ciphertext.resize(encrypted_len);
      std::cout << "Encrypted with AES-256-CBC-CTS\n";

    }else if (algorithm == "blowfish") {
      ciphertext.resize(plaintext.size() + 1024);
      size_t encrpyted_len;

      int result = encrypt_with_password_BF(password.c_str(),
                                             plaintext.data(),
                                             plaintext.size(),
                                             ciphertext.data(),
                                             &encrypted_len);

      if (result < 0) {
        std::cerr << "Error: Blowfish encryption failed\n";
        return 1;
      }
      ciphertext.resize(encrypted_len);
      std::cout << "Encrypted with Blowfish-CBC\n";

    }else if (algorithm == "rsa") {
      if (file_size > 245) {
        std::cerr << "Error: File too large for RSA encryption\n";
        std::cerr << "Maximum size for 2048-bit RSA: 245 bytes\n";
        std::cerr << "Your file: " << file_size << " bytes\n";
        std::cerr << "Tip: Use AES or Blowfish for large files\n";
        return 1;
      }

      std::string public_key = load_public_key(key_file);

      std::string encrypted_base64 = rsa_encrypt_public(public_key,
                                                      plaintext.data(),
                                                      plaintext.size());

      ciphertext.assign(encrypted_base64.begin(), encrypted_base64.end());
      std::cout << "Encrypted with RSA-2048\n";
    }


    std::ofstream outfile(output_file, std::ios::binary);
    if (!outfile) {
      std::cerr << "Error: Cannot create output file: " << output_file << "\n";
      return 1;
    }

    outfile.write((char*)ciphertext.data(), ciphertext.size());
    outfile.close();

    std::cout << "✓ Encrypted file saved: " << output_file << "\n";
    std::cout << "  Output size: " << ciphertext.size() << " bytes\n";

    return 0;

  } catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << "\n";
    return 1;
  }

}
