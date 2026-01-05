#include "iparser.h"

InputParser::InputParser(int &argc, char **argv) {
    for (int i = 1; i < argc; ++i)
        this->tokens.push_back(std::string(argv[i]));
}

const std::string& InputParser::getCmdOption(const std::string &option) const {
    auto itr = std::find(this->tokens.begin(), this->tokens.end(), option);
    if (itr != this->tokens.end() && ++itr != this->tokens.end()) {
        return *itr;
    }
    static const std::string empty_string("");
    return empty_string;
}

bool InputParser::cmdOptionExists(const std::string &option) const {
    return std::find(this->tokens.begin(), this->tokens.end(), option) != this->tokens.end();
}

const std::string CLIENT_HELP_MESSAGE = 
    "Help:\n"
    "     -u username\n";
const std::string SERVER_HELP_MESSAGE = "";