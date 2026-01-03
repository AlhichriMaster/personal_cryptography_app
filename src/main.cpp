#include "../include/CLI.h"
#include <iostream>

int main(int argc, char* argv[]) {

    if (argc < 2) {
        std::cout << "\n";
        std::cout << "Cryptography Application v1.0\n";
        std::cout << "Usage: crypto [COMMAND] [OPTIONS]\n";
        std::cout << "\n";
        std::cout << "Try 'crypto help' for more information.\n";
        std::cout << "\n";
        return 1;
    }

    CommandLineParser parser(argc, argv);
    std::string command = parser.getCommand();

    if (command == "help") {
      if (argc > 2) {
        parser.printCommandHelp(argv[2]);
      } else {
        parser.printUsage();
      }
      return 0;
    }

    int result = 1;

    if (command == "hash") {
        result = handle_hash_command(parser);
    } else if (command == "encrypt") {
        result = handle_encrypt_command(parser);
    } else if (command == "decrypt") {
        result = handle_decrypt_command(parser);
    } else if (command == "keygen") {
        result = handle_keygen_command(parser);
    } else if (command == "sign") {
        result = handle_sign_command(parser);
    } else if (command == "verify") {
        result = handle_verify_command(parser);
    } else {
        std::cerr << "Unknown command: " << command << "\n";
        std::cerr << "Try 'crypto help' for usage information.\n";
        result = 1;
    }

    return result;
}
