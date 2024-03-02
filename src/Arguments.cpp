#include "Arguments.hpp"

#include "Zip.hpp"
#include "file.hpp"

#include <algorithm>
#include <bitset>
#include <thread>
#include <type_traits>
#include <variant>

namespace
{

auto charRange(char first, char last) -> std::bitset<256>
{
    auto bitset = std::bitset<256>{};

    do
    {
        bitset.set(first);
    } while (first++ != last);

    return bitset;
}

template <typename F>
auto translateIntParseError(F&& f, const std::string& value)
{
    try
    {
        return f(value);
    }
    catch (const std::invalid_argument&)
    {
        throw Arguments::Error{"expected an integer, got \"" + value + "\""};
    }
    catch (const std::out_of_range&)
    {
        throw Arguments::Error{"integer value " + value + " is out of range"};
    }
}

auto parseInt(const std::string& value) -> int
{
    return translateIntParseError([](const std::string& value) { return std::stoi(value, nullptr, 0); }, value);
}

auto parseSize(const std::string& value) -> std::size_t
{
    return translateIntParseError([](const std::string& value) { return std::stoull(value, nullptr, 0); }, value);
}

auto parseInterval(const std::string& value) -> std::variant<Arguments::LengthInterval, std::size_t>
{
    const auto separator = std::string{".."};

    if (const auto minEnd = value.find(separator); minEnd != std::string::npos)
    {
        auto interval = Arguments::LengthInterval{};

        if (0 < minEnd)
            interval.minLength = parseSize(value.substr(0, minEnd));

        if (const auto maxBegin = minEnd + separator.size(); maxBegin < value.size())
            interval.maxLength = parseSize(value.substr(maxBegin));

        return interval;
    }
    else
        return parseSize(value);
}

} // namespace

Arguments::Error::Error(const std::string& description)
: BaseError{"Arguments error", description}
{
}

Arguments::Arguments(int argc, const char* argv[])
: jobs{[]() -> int
       {
           const auto concurrency = std::thread::hardware_concurrency();
           return concurrency ? concurrency : 2;
       }()}
, m_current{argv + 1}
, m_end{argv + argc}
{
    // parse arguments
    while (!finished())
        parseArgument();

    if (help || version || infoArchive)
        return; // no further checks are needed for those options

    // check constraints on arguments
    if (keys)
    {
        if (!decipheredFile && !changePassword && !changeKeys && !bruteforce)
            throw Error{"-d, -U, --change-keys or --bruteforce parameter is missing (required by -k)"};
    }
    else if (!password)
    {
        if (cipherFile && cipherIndex)
            throw Error{"-c and --cipher-index cannot be used at the same time"};
        if (plainFile && plainIndex)
            throw Error{"-p and --plain-index cannot be used at the same time"};

        if (!cipherFile && !cipherIndex)
            throw Error{"-c or --cipher-index parameter is missing"};
        if (!plainFile && !plainIndex && extraPlaintext.empty())
            throw Error{"-p, --plain-index or -x parameter is missing"};

        if (plainArchive && !plainFile && !plainIndex)
            throw Error{"-p or --plain-index parameter is missing (required by -P)"};

        if (cipherIndex && !cipherArchive)
            throw Error{"-C parameter is missing (required by --cipher-index)"};
        if (plainIndex && !plainArchive)
            throw Error{"-P parameter is missing (required by --plain-index)"};

        constexpr auto minimumOffset = -static_cast<int>(Data::encryptionHeaderSize);
        if (offset < minimumOffset)
            throw Error{"plaintext offset " + std::to_string(offset) + " is too small (minimum is " +
                        std::to_string(minimumOffset) + ")"};
    }

    if (decipheredFile && !cipherFile && !cipherIndex)
        throw Error{"-c or --cipher-index parameter is missing (required by -d)"};
    if (decipheredFile && !cipherArchive && decipheredFile == cipherFile)
        throw Error{"-c and -d parameters must point to different files"};

    if (changePassword && !cipherArchive)
        throw Error{"-C parameter is missing (required by -U)"};
    if (changePassword && changePassword->unlockedArchive == cipherArchive)
        throw Error{"-C and -U parameters must point to different files"};

    if (changeKeys && !cipherArchive)
        throw Error{"-C parameter is missing (required by --change-keys)"};
    if (changeKeys && changeKeys->unlockedArchive == cipherArchive)
        throw Error{"-C and --change-keys parameters must point to different files"};

    if (length && !bruteforce)
        throw Error{"--bruteforce parameter is missing (required by --length)"};
}

auto Arguments::loadData() const -> Data
{
    // load known plaintext
    auto plaintext = std::vector<std::uint8_t>{};
    if (plainArchive)
    {
        const auto archive = Zip{*plainArchive};
        const auto entry   = plainFile ? archive[*plainFile] : archive[*plainIndex];
        Zip::checkEncryption(entry, Zip::Encryption::None);
        plaintext = archive.load(entry, plainFilePrefix);
    }
    else if (plainFile)
        plaintext = loadFile(*plainFile, plainFilePrefix);

    // load ciphertext needed by the attack
    auto needed = Data::encryptionHeaderSize;
    if (!plaintext.empty())
        needed = std::max(needed, Data::encryptionHeaderSize + offset + plaintext.size());
    if (!extraPlaintext.empty())
        needed = std::max(needed, Data::encryptionHeaderSize + extraPlaintext.rbegin()->first + 1);

    auto ciphertext                  = std::vector<std::uint8_t>{};
    auto extraPlaintextWithCheckByte = std::optional<std::map<int, std::uint8_t>>{};
    if (cipherArchive)
    {
        const auto archive = Zip{*cipherArchive};
        const auto entry   = cipherFile ? archive[*cipherFile] : archive[*cipherIndex];
        Zip::checkEncryption(entry, Zip::Encryption::Traditional);
        ciphertext = archive.load(entry, needed);

        if (!ignoreCheckByte && !extraPlaintext.count(-1))
        {
            extraPlaintextWithCheckByte        = extraPlaintext;
            (*extraPlaintextWithCheckByte)[-1] = entry.checkByte;
        }
    }
    else
        ciphertext = loadFile(*cipherFile, needed);

    return {std::move(ciphertext), std::move(plaintext), offset, extraPlaintextWithCheckByte.value_or(extraPlaintext)};
}

auto Arguments::LengthInterval::operator&(const Arguments::LengthInterval& other) const -> Arguments::LengthInterval
{
    return {std::max(minLength, other.minLength), std::min(maxLength, other.maxLength)};
}

auto Arguments::finished() const -> bool
{
    return m_current == m_end;
}

void Arguments::parseArgument()
{
    switch (readOption("an option"))
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
        auto i = readInt("offset");
        for (const auto b : readHex("data"))
            extraPlaintext[i++] = b;
        break;
    }
    case Option::ignoreCheckByte:
        ignoreCheckByte = true;
        break;
    case Option::attackStart:
        attackStart = readInt("checkpoint");
        break;
    case Option::password:
        password = readString("password");
        break;
    case Option::keys:
        keys = {readKey("X"), readKey("Y"), readKey("Z")};
        break;
    case Option::decipheredFile:
        decipheredFile = readString("decipheredfile");
        break;
    case Option::keepHeader:
        keepHeader = true;
        break;
    case Option::changePassword:
        changePassword = {readString("unlockedzip"), readString("password")};
        break;
    case Option::changeKeys:
        changeKeys = {readString("unlockedzip"), {readKey("X"), readKey("Y"), readKey("Z")}};
        break;
    case Option::bruteforce:
        bruteforce = readCharset();
        break;
    case Option::length:
        length = length.value_or(LengthInterval{}) &
                 std::visit(
                     [](auto arg)
                     {
                         if constexpr (std::is_same_v<decltype(arg), std::size_t>)
                             return LengthInterval{arg, arg}; // a single value is interpreted as an exact length
                         else
                             return arg;
                     },
                     parseInterval(readString("length")));
        break;
    case Option::recoverPassword:
        length = length.value_or(LengthInterval{}) &
                 std::visit(
                     [](auto arg)
                     {
                         if constexpr (std::is_same_v<decltype(arg), std::size_t>)
                             return LengthInterval{0, arg}; // a single value is interpreted as an interval 0..max
                         else
                             return arg;
                     },
                     parseInterval(readString("length")));
        bruteforce = readCharset();
        break;
    case Option::recoveryStart:
    {
        const auto checkpoint = readHex("checkpoint");
        recoveryStart.assign(checkpoint.begin(), checkpoint.end());
        break;
    }
    case Option::jobs:
        jobs = readInt("count");
        break;
    case Option::exhaustive:
        exhaustive = true;
        break;
    case Option::infoArchive:
        infoArchive = readString("zipfile");
        break;
    case Option::version:
        version = true;
        break;
    case Option::help:
        help = true;
        break;
    }
}

auto Arguments::readString(const std::string& description) -> std::string
{
    if (finished())
        throw Error{"expected " + description + ", got nothing"};

    return *m_current++;
}

auto Arguments::readOption(const std::string& description) -> Arguments::Option
{
    // clang-format off
#define PAIR(string, option) {#string, Option::option}
#define PAIRS(short, long, option) PAIR(short, option), PAIR(long, option)

    static const auto stringToOption = std::map<std::string, Option>{
        PAIRS(-c, --cipher-file,       cipherFile),
        PAIR (    --cipher-index,      cipherIndex),
        PAIRS(-C, --cipher-zip,        cipherArchive),
        PAIRS(-p, --plain-file,        plainFile),
        PAIR (    --plain-index,       plainIndex),
        PAIRS(-P, --plain-zip,         plainArchive),
        PAIRS(-t, --truncate,          plainFilePrefix),
        PAIRS(-o, --offset,            offset),
        PAIRS(-x, --extra,             extraPlaintext),
        PAIR (    --ignore-check-byte, ignoreCheckByte),
        PAIR (    --continue-attack,   attackStart),
        PAIR (    --password,          password),
        PAIRS(-k, --keys,              keys),
        PAIRS(-d, --decipher,          decipheredFile),
        PAIR (    --keep-header,       keepHeader),
        PAIRS(-U, --change-password,   changePassword),
        PAIR (    --change-keys,       changeKeys),
        PAIRS(-b, --bruteforce,        bruteforce),
        PAIRS(-l, --length,            length),
        PAIRS(-r, --recover-password,  recoverPassword),
        PAIR (    --continue-recovery, recoveryStart),
        PAIRS(-j, --jobs,              jobs),
        PAIRS(-e, --exhaustive,        exhaustive),
        PAIRS(-L, --list,              infoArchive),
        PAIR (    --version,           version),
        PAIRS(-h, --help,              help),
    };
    // clang-format on

#undef PAIR
#undef PAIRS

    const auto str = readString(description);
    if (const auto it = stringToOption.find(str); it == stringToOption.end())
        throw Error{"unknown option " + str};
    else
        return it->second;
}

auto Arguments::readInt(const std::string& description) -> int
{
    return parseInt(readString(description));
}

auto Arguments::readSize(const std::string& description) -> std::size_t
{
    return parseSize(readString(description));
}

auto Arguments::readHex(const std::string& description) -> std::vector<std::uint8_t>
{
    const auto str = readString(description);

    if (str.size() % 2)
        throw Error{"expected an even-length string, got " + str};
    if (!std::all_of(str.begin(), str.end(), [](char c) { return std::isxdigit(static_cast<unsigned char>(c)); }))
        throw Error{"expected " + description + " in hexadecimal, got " + str};

    auto data = std::vector<std::uint8_t>{};
    for (auto i = std::size_t{}; i < str.length(); i += 2)
        data.push_back(static_cast<std::uint8_t>(std::stoul(str.substr(i, 2), nullptr, 16)));

    return data;
}

auto Arguments::readKey(const std::string& description) -> std::uint32_t
{
    const auto str = readString(description);

    if (str.size() > 8)
        throw Error{"expected a string of length 8 or less, got " + str};
    if (!std::all_of(str.begin(), str.end(), [](char c) { return std::isxdigit(static_cast<unsigned char>(c)); }))
        throw Error{"expected " + description + " in hexadecimal, got " + str};

    return static_cast<std::uint32_t>(std::stoul(str, nullptr, 16));
}

auto Arguments::readCharset() -> std::vector<std::uint8_t>
{
    const auto lowercase   = charRange('a', 'z');
    const auto uppercase   = charRange('A', 'Z');
    const auto digits      = charRange('0', '9');
    const auto alphanum    = lowercase | uppercase | digits;
    const auto printable   = charRange(' ', '~');
    const auto punctuation = printable & ~alphanum;

    const auto charsetArg = readString("charset");
    if (charsetArg.empty())
        throw Error{"the charset for password recovery is empty"};

    auto charset = std::bitset<256>{};

    for (auto it = charsetArg.begin(); it != charsetArg.end(); ++it)
    {
        if (*it == '?') // escape character for predefined charsets
        {
            if (++it == charsetArg.end())
            {
                charset.set('?');
                break;
            }

            switch (*it)
            {
                // clang-format off
            case 'l': charset |= lowercase;   break;
            case 'u': charset |= uppercase;   break;
            case 'd': charset |= digits;      break;
            case 's': charset |= punctuation; break;
            case 'a': charset |= alphanum;    break;
            case 'p': charset |= printable;   break;
            case 'b': charset.set();          break;
            case '?': charset.set('?');       break;
                // clang-format on
            default:
                throw Error{std::string{"unknown charset ?"} + *it};
            }
        }
        else
            charset.set(*it);
    }

    auto result = std::vector<std::uint8_t>{};
    for (auto c = 0; c < 256; c++)
        if (charset[c])
            result.push_back(c);

    return result;
}
