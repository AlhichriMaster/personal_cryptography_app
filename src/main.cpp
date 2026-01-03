#include "../include/CLI.h"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Cryptography Application v1.0\n";
        std::cout << "Usage: crypto [COMMAND] [OPTIONS]\n";
        std::cout << "Try 'crypto help' for more information.\n";
        return 1;
    }

    CommandLineParser parser(argc, argv);
    std::string command = parser.getCommand();

    if (command == "hash") {
        return handle_hash_command(parser);
    } else if (command == "encrypt") {
        return handle_encrypt_command(parser);
    } else if (command == "decrypt") {
        return handle_decrypt_command(parser);
    } else if (command == "keygen") {
        return handle_keygen_command(parser);
    } else if (command == "sign") {
        return handle_sign_command(parser);
    } else if (command == "verify") {
        return handle_verify_command(parser);
    } else if (command == "help") {
        parser.printUsage();
        return 0;
    } else {
        std::cerr << "Unknown command: " << command << "\n";
        std::cerr << "Try 'crypto help' for usage information.\n";
        return 1;
    }
}
