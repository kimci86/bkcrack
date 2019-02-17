#include "Arguments.hpp"

Arguments::Error::Error(const std::string& description)
 : std::logic_error(description)
{}

void Arguments::parse(int argc, const char* argv[])
{
    // parse arguments
    this->argc = argc;
    this->argv = argv;
    this->current = argv + 1;
    while(!finished())
        parseArgument();

    // check mandatory arguments
    if(!help)
    {
        if(cipherfile.empty())
            throw Error("-c parameter is missing");
        if(!keysGiven && plainfile.empty())
            throw Error("-p parameter is missing");
        if(keysGiven && decipheredfile.empty())
            throw Error("-d parameter is missing");
    }
}

bool Arguments::finished() const
{
    return current == argv + argc;
}

void Arguments::parseArgument()
{
    switch(char flag = readFlag("a flag"))
    {
        case 'c':
            cipherfile = readString("ciphertext");
            break;
        case 'p':
            plainfile = readString("plaintext");
            break;
        case 'C':
            cipherarchive = readString("encryptedzip");
            break;
        case 'P':
            plainarchive = readString("plainzip");
            break;
        case 'd':
            decipheredfile = readString("decipheredfile");
            break;
        case 'o':
            offset = readInt("offset");
            break;
        case 'k':
        {
            // read x, y and z before calling Keys constructor to guarantee evaluation order
            dword x = readKey("X"),
                  y = readKey("Y"),
                  z = readKey("Z");
            keys = Keys(x, y, z);
            keysGiven = true;
            break;
        }
        case 'h':
            help = true;
            break;
        default:
            throw Error(std::string("unknown flag ")+flag);
    }
}

std::string Arguments::readString(const std::string& description)
{
    if(finished())
        throw Error("expected "+description+", got nothing");

    return std::string(*current++);
}

char Arguments::readFlag(const std::string& description)
{
    const std::string& flag = readString(description);

    if(flag.size() != 2 || flag.front() != '-')
        throw Error("expected "+description+", got "+flag);

    return flag[1];
}

int Arguments::readInt(const std::string& description)
{
    return std::stoi(readString(description), nullptr, 0);
}

dword Arguments::readKey(const std::string& description)
{
    return std::stoul(readString(description), nullptr, 16);
}
