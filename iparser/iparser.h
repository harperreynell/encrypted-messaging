#include <string>
#include <vector>

class InputParser{
public:
    InputParser(int &argc, char **argv);

    const std::string& getCmdOption(const std::string &option) const;
    bool cmdOptionExists(const std::string &option) const;
private:
    std::vector<std::string> tokens;
};

extern const std::string CLIENT_HELP_MESSAGE;
extern const std::string SERVER_HELP_MESSAGE;
