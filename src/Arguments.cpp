#include "Arguments.hpp"
#include "Data.hpp"
#include <algorithm>
#include <bitset>

namespace
{

std::bitset<256> charRange(char first, char last)
{
    std::bitset<256> bitset;

    do
    {
        bitset.set(first);
    } while(first++ != last);

    return bitset;
}

} // namespace

Arguments::Error::Error(const std::string& description)
 : BaseError("Arguments error", description)
{}

Arguments::Arguments(int argc, const char* argv[])
{
    // parse arguments
    this->argc = argc;
    this->argv = argv;
    this->current = argv + 1;
    while(!finished())
        parseArgument();

    if(help)
        return;

    // check mandatory arguments
    if(keysGiven)
    {
        if(decipheredfile.empty() && unlockedarchive.empty() && maxLength == 0)
            throw Error("-d, -U or -r parameter is missing (required by -k)");
    }
    else
    {
        if(cipherfile.empty())
            throw Error("-c parameter is missing");
        if(plainfile.empty())
            throw Error("-p parameter is missing");
    }

    if(!decipheredfile.empty() && cipherfile.empty())
        throw Error("-c parameter is missing (required by -d)");
    if(!decipheredfile.empty() && decipheredfile == cipherfile)
        throw Error("-c and -d parameters should point to different files");
    if(!unlockedarchive.empty() && cipherarchive.empty())
        throw Error("-C parameter is missing (required by -U)");
    if(!unlockedarchive.empty() && unlockedarchive == cipherarchive)
        throw Error("-C and -U parameters should point to different files");

    // check that offset is not too small
    if(offset < -static_cast<int>(Data::ENCRYPTION_HEADER_SIZE))
        throw Error("plaintext offset "+std::to_string(offset)+" is too small");

    // check that extra plaintext offsets are not too small
    if(!extraPlaintext.empty() && extraPlaintext.begin()->first < -static_cast<int>(Data::ENCRYPTION_HEADER_SIZE))
        throw Error("extra plaintext offset "+std::to_string(extraPlaintext.begin()->first)+" is too small");
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
        case 'U':
            unlockedarchive = readString("unlockedzip");
            newPassword = readString("password");
            break;
        case 'd':
            decipheredfile = readString("decipheredfile");
            break;
        case 'o':
            offset = readInt("offset");
            break;
        case 't':
            plainsize = readSize("size");
            break;
        case 'x':
        {
            int i = readInt("offset");
            for(byte b : readHex("data"))
                extraPlaintext[i++] = b;
            break;
        }
        case 'e':
            exhaustive = true;
            break;
        case 'k':
            keys = readKeys();
            keysGiven = true;
            break;
        case 'r':
            maxLength = readSize("length");
            charset = readCharset();
            break;
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

std::size_t Arguments::readSize(const std::string& description)
{
    return std::stoull(readString(description), nullptr, 0);
}

bytevec Arguments::readHex(const std::string& description)
{
    std::string str = readString(description);

    if(str.size() % 2)
        throw Error("expected an even-length string, got "+str);
    if(!std::all_of(str.begin(), str.end(), [](unsigned char c){ return std::isxdigit(c); }))
        throw Error("expected "+description+" in hexadecimal, got "+str);

    bytevec data;
    for(std::size_t i = 0; i < str.length(); i += 2)
        data.push_back(static_cast<byte>(std::stoul(str.substr(i, 2), nullptr, 16)));

    return data;
}

uint32 Arguments::readKey(const std::string& description)
{
    std::string str = readString(description);

    if(str.size() > 8)
        throw Error("expected a string of length 8 or less, got "+str);
    if(!std::all_of(str.begin(), str.end(), [](unsigned char c){ return std::isxdigit(c); }))
        throw Error("expected "+description+" in hexadecimal, got "+str);

    return static_cast<uint32>(std::stoul(str, nullptr, 16));
}

Keys Arguments::readKeys()
{
    // read x, y and z before calling Keys constructor to guarantee evaluation order
    uint32 x = readKey("X"),
           y = readKey("Y"),
           z = readKey("Z");
    return Keys(x, y, z);
}

bytevec Arguments::readCharset()
{
    const std::bitset<256>
        lowercase   = charRange('a', 'z'),
        uppercase   = charRange('A', 'Z'),
        digits      = charRange('0', '9'),
        alphanum    = lowercase | uppercase | digits,
        printable   = charRange(' ', '~'),
        punctuation = printable & ~alphanum;

    const std::string charsetArg = readString("charset");
    if(charsetArg.empty())
        throw Error("the charset for password recovery is empty");

    std::bitset<256> charset;

    for(auto it = charsetArg.begin(); it != charsetArg.end(); ++it)
    {
        if(*it == '?') // escape character for predefined charsets
        {
            if(++it == charsetArg.end())
            {
                charset.set('?');
                break;
            }

            switch(*it)
            {
                case 'l': charset |= lowercase;   break;
                case 'u': charset |= uppercase;   break;
                case 'd': charset |= digits;      break;
                case 's': charset |= punctuation; break;
                case 'a': charset |= alphanum;    break;
                case 'p': charset |= printable;   break;
                case 'b': charset.set();          break;
                case '?': charset.set('?');       break;

                default:
                    throw Error(std::string("unknown charset ?")+*it);
            }
        }
        else
            charset.set(*it);
    }

    bytevec result;
    for(int c = 0; c < 256; c++)
        if(charset[c])
            result.push_back(c);

    return result;
}
