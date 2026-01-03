#ifndef CLI_H
#define CLI_H

#include <string>
#include <map>
#include <vector>

class CommandLineParser {
private:
  std::map<std::string, std::string> options;
  std::string command;
  std::vector<std::string>args;

public:
  /**
   * @brief Constructor - parses command-line arguments
   * @param argc Argument count from main()
   * @param argv Argument values from main()
   */
  CommandLineParser(int argc, char* argv[]);

  /**
   * @brief Get the main command
   * @return Command string (first argument after program name)
   */
  std::string getCommand() const { return command; }


  /**
   * @brief Get an option value
   * @param key Option key (e.g., "-a", "-f")
   * @param default_val Default value if option not found
   * @return Option value or default
   */
  std::string getOption(const std::string& key, const std::string& default_val = "") const;

  /**
   * @brief Check if an option exists
   * @param key Option key to check
   * @return true if option was provided
   */
  bool hasOption(const std::string& key) const;

  /**
   * @brief Print usage information
   */
  void printUsage() const;

  /**
   * @brief Princt detailed help for a specific command
   * @param cmd Command name
   */
  void printCommandHelp(const std::string& cmd) const;
};

//Command handlers
int handle_hash_command(const CommandLineParser& parser);
int handle_encrypt_command(const CommandLineParser& parser);
int handle_decrypt_command(const CommandLineParser& parser);
int handle_keygen_command(const CommandLineParser& parser);
int handle_sign_command(const CommandLineParser& parser);
int handle_verify_command(const CommandLineParser& parser);


#endif // CLI_H_
