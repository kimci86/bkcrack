#include "Arguments.hpp"
#include "file.hpp"
#include "zip.hpp"
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
: m_current{argv + 1}, m_end{argv + argc}
{
    // parse arguments
    while(!finished())
        parseArgument();

    if(help)
        return;

    if(infoArchive)
        return;

    // check constraints on arguments
    if(keys)
    {
        if(!decipheredFile && !changePassword && !recoverPassword)
            throw Error("-d, -U or -r parameter is missing (required by -k)");
    }
    else
    {
        if(cipherFile && cipherIndex)
            throw Error("-c and --cipher-index cannot be used at the same time");
        if(plainFile && plainIndex)
            throw Error("-p and --plain-index cannot be used at the same time");

        if(!cipherFile && !cipherIndex)
            throw Error("-c or --cipher-index parameter is missing");
        if(!plainFile && !plainIndex && extraPlaintext.empty())
            throw Error("-p, --plain-index or -x parameter is missing");

        if(plainArchive && !plainFile && !plainIndex)
            throw Error("-p or --plain-index parameter is missing (required by -P)");

        if(cipherIndex && !cipherArchive)
            throw Error("-C parameter is missing (required by --cipher-index)");
        if(plainIndex && !plainArchive)
            throw Error("-P parameter is missing (required by --plain-index)");

        constexpr int minimumOffset = -static_cast<int>(Data::ENCRYPTION_HEADER_SIZE);
        if(offset < minimumOffset)
            throw Error("plaintext offset "+std::to_string(offset)+" is too small (minimum is "+std::to_string(minimumOffset)+")");
    }

    if(decipheredFile && !cipherFile && !cipherIndex)
        throw Error("-c or --cipher-index parameter is missing (required by -d)");
    if(decipheredFile && !cipherArchive && decipheredFile == cipherFile)
        throw Error("-c and -d parameters must point to different files");

    if(changePassword && !cipherArchive)
        throw Error("-C parameter is missing (required by -U)");
    if(changePassword && changePassword->unlockedArchive == cipherArchive)
        throw Error("-C and -U parameters must point to different files");
}

Data Arguments::loadData() const
{
    // load known plaintext
    bytevec plaintext;
    if(plainArchive)
    {
        if(plainFile)
            plaintext = loadZipEntry(*plainArchive, *plainFile, ZipEntry::Encryption::None, plainFilePrefix);
        else
            plaintext = loadZipEntry(*plainArchive, *plainIndex, ZipEntry::Encryption::None, plainFilePrefix);
    }
    else if(plainFile)
        plaintext = loadFile(*plainFile, plainFilePrefix);

    // load ciphertext needed by the attack
    std::size_t needed = Data::ENCRYPTION_HEADER_SIZE;
    if(!plaintext.empty())
        needed = std::max(needed, Data::ENCRYPTION_HEADER_SIZE + offset + plaintext.size());
    if(!extraPlaintext.empty())
        needed = std::max(needed, Data::ENCRYPTION_HEADER_SIZE + extraPlaintext.rbegin()->first + 1);

    bytevec ciphertext;
    if(cipherArchive)
    {
        if(cipherFile)
            ciphertext = loadZipEntry(*cipherArchive, *cipherFile, ZipEntry::Encryption::Traditional, needed);
        else
            ciphertext = loadZipEntry(*cipherArchive, *cipherIndex, ZipEntry::Encryption::Traditional, needed);
    }
    else
        ciphertext = loadFile(*cipherFile, needed);

    return Data(std::move(ciphertext), std::move(plaintext), offset, extraPlaintext);
}

bool Arguments::finished() const
{
    return m_current == m_end;
}

void Arguments::parseArgument()
{
    switch(readOption("an option"))
    {
        case Option::cipherFile:
            cipherFile = readString("ciphertext");
            break;
        case Option::cipherIndex:
            cipherIndex = readSize("index");
            break;
        case Option::cipherArchive:
            cipherArchive = readString("encryptedzip");
            break;
        case Option::plainFile:
            plainFile = readString("plaintext");
            break;
        case Option::plainIndex:
            plainIndex = readSize("index");
            break;
        case Option::plainArchive:
            plainArchive = readString("plainzip");
            break;
        case Option::plainFilePrefix:
            plainFilePrefix = readSize("size");
            break;
        case Option::offset:
            offset = readInt("offset");
            break;
        case Option::extraPlaintext:
        {
            int i = readInt("offset");
            for(byte b : readHex("data"))
                extraPlaintext[i++] = b;
            break;
        }
        case Option::exhaustive:
            exhaustive = true;
            break;
        case Option::keys:
            keys = readKeys();
            break;
        case Option::decipheredFile:
            decipheredFile = readString("decipheredfile");
            break;
        case Option::changePassword:
        {
            std::string unlockedArchive = readString("unlockedzip");
            std::string newPassword = readString("password");
            changePassword = {std::move(unlockedArchive), std::move(newPassword)};
            break;
        }
        case Option::recoverPassword:
        {
            std::size_t maxLength = readSize("length");
            bytevec charset = readCharset();
            recoverPassword = {maxLength, std::move(charset)};
            break;
        }
        case Option::infoArchive:
            infoArchive = readString("zipfile");
            break;
        case Option::help:
            help = true;
            break;
    }
}

std::string Arguments::readString(const std::string& description)
{
    if(finished())
        throw Error("expected "+description+", got nothing");

    return *m_current++;
}

Arguments::Option Arguments::readOption(const std::string& description)
{
    #define PAIRS(short, long, option) {#short, Option::option}, {#long, Option::option}
    static const std::map<std::string, Option> stringToOption = {
        PAIRS(-c, --cipher-file,      cipherFile),
        {"--cipher-index", Option::cipherIndex},
        PAIRS(-C, --cipher-zip,       cipherArchive),
        PAIRS(-p, --plain-file,       plainFile),
        {"--plain-index", Option::plainIndex},
        PAIRS(-P, --plain-zip,        plainArchive),
        PAIRS(-t, --truncate,         plainFilePrefix),
        PAIRS(-o, --offset,           offset),
        PAIRS(-x, --extra,            extraPlaintext),
        PAIRS(-e, --exhaustive,       exhaustive),
        PAIRS(-k, --keys,             keys),
        PAIRS(-d, --decipher,         decipheredFile),
        PAIRS(-U, --change-password,  changePassword),
        PAIRS(-r, --recover-password, recoverPassword),
        PAIRS(-L, --list,             infoArchive),
        PAIRS(-h, --help,             help)
    };
    #undef PAIRS

    std::string str = readString(description);
    if(auto it = stringToOption.find(str); it == stringToOption.end())
        throw Error("unknown option "+str);
    else
        return it->second;
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
