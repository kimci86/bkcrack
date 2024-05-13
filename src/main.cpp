#include "Arguments.hpp"
#include "Attack.hpp"
#include "ConsoleProgress.hpp"
#include "Data.hpp"
#include "SigintHandler.hpp"
#include "VirtualTerminalSupport.hpp"
#include "Zip.hpp"
#include "Zreduction.hpp"
#include "file.hpp"
#include "log.hpp"
#include "password.hpp"
#include "version.hpp"

#include <cassert>
#include <iomanip>
#include <limits>

namespace
{

const char* const usage = R"_(usage: bkcrack [options]
Crack legacy zip encryption with Biham and Kocher's known plaintext attack.

Options to get the internal password representation:
 -c, --cipher-file <file>    Zip entry or file on disk containing ciphertext
     --cipher-index <index>  Index of the zip entry containing ciphertext
 -C, --cipher-zip <archive>  Zip archive containing the ciphertext entry

 -p, --plain-file <file>     Zip entry or file on disk containing plaintext
     --plain-index <index>   Index of the zip entry containing plaintext
 -P, --plain-zip <archive>   Zip archive containing the plaintext entry
 -t, --truncate <size>       Maximum number of bytes of plaintext to load
 -o, --offset <offset>       Known plaintext offset relative to ciphertext
                              without encryption header (may be negative)
 -x, --extra <offset> <data> Additional plaintext in hexadecimal starting
                              at the given offset (may be negative)
     --ignore-check-byte     Do not automatically use ciphertext's check byte
                              as known plaintext

     --continue-attack <checkpoint>
        Starting point of the attack. Useful to continue a previous
        non-exhaustive or interrupted attack.

     --password <password>
        Password from which to derive the internal password representation.
        Useful for testing purposes and advanced scenarios such as reverting
        the effect of the --change-password command.

Options to use the internal password representation:
 -k, --keys <X> <Y> <Z>      Internal password representation as three 32-bits
                              integers in hexadecimal (requires -d, -U,
                              --change-keys or --bruteforce)

 -d, --decipher <file>       File to write the deciphered data (requires -c)
     --keep-header           Write the encryption header at the beginning of
                              deciphered data instead of discarding it

 -U, --change-password <archive> <password>
        Create a copy of the encrypted zip archive with the password set to the
        given new password (requires -C)

     --change-keys <archive> <X> <Y> <Z>
        Create a copy of the encrypted zip archive using the given new internal
        password representation (requires -C)

 -b, --bruteforce <charset>
        Try to recover the password or an equivalent one by generating and
        testing password candidates using characters in the given charset.
        The charset is a sequence of characters or shortcuts for predefined
        charsets listed below. Example: ?l?d-.@

          ?l lowercase letters              abcdefghijklmnopqrstuvwxyz
          ?u uppercase letters              ABCDEFGHIJKLMNOPQRSTUVWXYZ
          ?d decimal digits                 0123456789
          ?s special characters              !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
          ?a alpha-numerical characters     (same as ?l?u?d)
          ?p printable ASCII characters     (same as ?l?u?d?s)
          ?b all bytes                      (0x00 - 0xff)

 -l, --length [ <min>..<max> | <min>.. | ..<max> | <length> ]
        Length interval or exact length of password candidates to generate and
        test during password recovery (requires --bruteforce)

 -r, --recover-password [ <min>..<max> | <min>.. | ..<max> | <max> ] <charset>
        Shortcut for --length and --bruteforce options

     --continue-recovery <checkpoint>
        Starting point of the password recovery. Useful to continue a previous
        non-exhaustive or interrupted password recovery.

Other options:
 -j, --jobs <count>          Number of threads to use for parallelized operations
 -e, --exhaustive            Exhaustively look for all solutions (keys or
                              passwords) instead of stopping after the first
                              solution is found
 -L, --list <archive>        List entries in a zip archive and exit
     --version               Show version information and exit
 -h, --help                  Show this help and exit)_";

void listEntries(const std::string& archiveFilename);

} // namespace

auto main(int argc, const char* argv[]) -> int
try
{
    // enable virtual terminal support on Windows, no-op on other platforms
    const auto vtSupport = VirtualTerminalSupport{};

    // version information
    std::cout << "bkcrack " << bkcrackVersion << " - " << bkcrackVersionDate << std::endl;

    const auto args = Arguments{argc, argv};
    if (args.help)
    {
        std::cout << usage << std::endl;
        return 0;
    }

    if (args.version)
    {
        // version information was already printed, nothing else to do
        return 0;
    }

    if (args.infoArchive)
    {
        listEntries(*args.infoArchive);
        return 0;
    }

    auto keysvec = std::vector<Keys>{};
    if (args.keys)
        keysvec.push_back(*args.keys);
    else if (args.password)
    {
        keysvec.emplace_back(*args.password);
        std::cout << "Internal representation for password \"" << *args.password << "\": " << keysvec.back()
                  << std::endl;
    }
    else
    // find keys from known plaintext
    {
        const auto data = args.loadData();

        // generate and reduce Zi[10,32) values
        auto zr = Zreduction{data.keystream};
        if (data.keystream.size() > Attack::contiguousSize)
        {
            std::cout << "[" << put_time << "] Z reduction using " << (data.keystream.size() - Attack::contiguousSize)
                      << " bytes of known plaintext" << std::endl;

            auto progress = ConsoleProgress{std::cout};
            zr.reduce(progress);
        }

        // generate Zi[2,32) values
        zr.generate();

        // carry out the attack on the remaining Zi[2,32) values
        std::cout << "[" << put_time << "] Attack on " << zr.getCandidates().size() << " Z values at index "
                  << (static_cast<int>(data.offset + zr.getIndex()) - static_cast<int>(Data::encryptionHeaderSize))
                  << std::endl;

        const auto [state, restart] = [&]() -> std::pair<Progress::State, int>
        {
            auto       start         = args.attackStart;
            auto       progress      = ConsoleProgress{std::cout};
            const auto sigintHandler = SigintHandler{progress.state};
            keysvec = attack(data, zr.getCandidates(), start, zr.getIndex(), args.jobs, args.exhaustive, progress);
            return {progress.state, start};
        }();

        if (state != Progress::State::Normal)
        {
            if (state == Progress::State::Canceled)
                std::cout << "Operation interrupted by user." << std::endl;
            else if (state == Progress::State::EarlyExit)
                std::cout << "Found a solution. Stopping." << std::endl;

            if (restart < static_cast<int>(zr.getCandidates().size()))
                std::cout << "You may resume the attack with the option: --continue-attack " << restart << std::endl;
        }

        // print the keys
        std::cout << "[" << put_time << "] ";
        if (keysvec.empty())
        {
            std::cout << "Could not find the keys." << std::endl;
            return 1;
        }
        else
        {
            std::cout << "Keys" << std::endl;
            for (const auto& keys : keysvec)
                std::cout << keys << std::endl;
        }
    }

    // From there, keysvec is not empty.

    const auto keys = keysvec.front();
    if ((args.decipheredFile || args.changePassword || args.changeKeys || args.bruteforce) && keysvec.size() > 1)
        std::cout << "Continuing with keys " << keys << "\n"
                  << "Use the command line option -k to provide other keys." << std::endl;

    // decipher
    if (args.decipheredFile)
    {
        std::cout << "[" << put_time << "] Writing deciphered data " << *args.decipheredFile << " (maybe compressed)";
        if (args.keepHeader)
            std::cout << " with encryption header";
        std::cout << std::endl;

        {
            auto cipherstream = openInput(args.cipherArchive ? *args.cipherArchive : *args.cipherFile);
            auto ciphersize   = std::numeric_limits<std::size_t>::max();

            if (args.cipherArchive)
            {
                const auto archive = Zip{cipherstream};
                const auto entry   = args.cipherFile ? archive[*args.cipherFile] : archive[*args.cipherIndex];
                Zip::checkEncryption(entry, Zip::Encryption::Traditional);

                archive.seek(entry);
                ciphersize = entry.packedSize;
            }

            auto decipheredstream = openOutput(*args.decipheredFile);

            decipher(cipherstream, ciphersize,
                     args.keepHeader ? 0 : static_cast<std::size_t>(Data::encryptionHeaderSize), decipheredstream,
                     keys);
        }

        std::cout << "Wrote deciphered data." << std::endl;
    }

    // unlock
    if (args.changePassword)
    {
        const auto& [unlockedArchive, newPassword] = *args.changePassword;

        std::cout << "[" << put_time << "] Writing unlocked archive " << unlockedArchive << " with password \""
                  << newPassword << "\"" << std::endl;

        {
            const auto archive  = Zip{*args.cipherArchive};
            auto       unlocked = openOutput(unlockedArchive);

            auto progress = ConsoleProgress{std::cout};
            archive.changeKeys(unlocked, keys, Keys{newPassword}, progress);
        }

        std::cout << "Wrote unlocked archive." << std::endl;
    }

    if (args.changeKeys)
    {
        const auto& [unlockedArchive, newKeys] = *args.changeKeys;

        std::cout << "[" << put_time << "] Writing unlocked archive " << unlockedArchive << " with keys " << newKeys
                  << std::endl;

        {
            const auto archive  = Zip{*args.cipherArchive};
            auto       unlocked = openOutput(unlockedArchive);

            auto progress = ConsoleProgress{std::cout};
            archive.changeKeys(unlocked, keys, newKeys, progress);
        }

        std::cout << "Wrote unlocked archive." << std::endl;
    }

    // recover password
    if (args.bruteforce)
    {
        std::cout << "[" << put_time << "] Recovering password" << std::endl;

        auto passwords = std::vector<std::string>{};

        const auto [state, restart] = [&]() -> std::pair<Progress::State, std::string>
        {
            const auto& charset                = *args.bruteforce;
            const auto& [minLength, maxLength] = args.length.value_or(Arguments::LengthInterval{});
            auto       start                   = args.recoveryStart;
            auto       progress                = ConsoleProgress{std::cout};
            const auto sigintHandler           = SigintHandler{progress.state};
            passwords = recoverPassword(keysvec.front(), charset, minLength, maxLength, start, args.jobs,
                                        args.exhaustive, progress);
            return {progress.state, start};
        }();

        if (state != Progress::State::Normal)
        {
            if (state == Progress::State::Canceled)
                std::cout << "Operation interrupted by user." << std::endl;
            else if (state == Progress::State::EarlyExit)
                std::cout << "Found a solution. Stopping." << std::endl;

            if (!restart.empty())
            {
                const auto flagsBefore = std::cout.setf(std::ios::hex, std::ios::basefield);
                const auto fillBefore  = std::cout.fill('0');

                std::cout << "You may resume the password recovery with the option: --continue-recovery ";
                for (const auto c : restart)
                    std::cout << std::setw(2) << static_cast<int>(c);
                std::cout << std::endl;

                std::cout.fill(fillBefore);
                std::cout.flags(flagsBefore);
            }
        }

        std::cout << "[" << put_time << "] ";
        if (passwords.empty())
        {
            std::cout << "Could not recover password" << std::endl;
            return 1;
        }
        else
        {
            std::cout << "Password" << std::endl;

            const auto flagsBefore = std::cout.setf(std::ios::hex, std::ios::basefield);
            const auto fillBefore  = std::cout.fill('0');

            for (const auto& password : passwords)
            {
                std::cout << "as bytes: ";
                for (const auto c : password)
                    std::cout << std::setw(2) << static_cast<int>(c) << ' ';
                std::cout << std::endl;
                std::cout << "as text: " << password << std::endl;
            }

            std::cout.fill(fillBefore);
            std::cout.flags(flagsBefore);
        }
    }

    return 0;
}
catch (const Arguments::Error& e)
{
    std::cout << e.what() << std::endl;
    std::cout << "Run 'bkcrack -h' for help." << std::endl;
    return 1;
}
catch (const BaseError& e)
{
    std::cout << e.what() << std::endl;
    return 1;
}

namespace
{

auto getEncryptionDescription(Zip::Encryption encryption) -> std::string
{
    switch (encryption)
    {
    case Zip::Encryption::None:
        return "None";
    case Zip::Encryption::Traditional:
        return "ZipCrypto";
    case Zip::Encryption::Unsupported:
        return "Other";
    }
    assert(false);

    return "";
}

auto getCompressionDescription(Zip::Compression compression) -> std::string
{
    switch (compression)
    {
#define CASE(c)                                                                                                        \
    case Zip::Compression::c:                                                                                          \
        return #c
        CASE(Store);
        CASE(Shrink);
        CASE(Implode);
        CASE(Deflate);
        CASE(Deflate64);
        CASE(BZip2);
        CASE(LZMA);
        CASE(Zstandard);
        CASE(MP3);
        CASE(XZ);
        CASE(JPEG);
        CASE(WavPack);
        CASE(PPMd);
#undef CASE
    }

    return "Other (" + std::to_string(static_cast<int>(compression)) + ")";
}

void listEntries(const std::string& archiveFilename)
{
    const auto archive = Zip{archiveFilename};

    std::cout << "Archive: " << archiveFilename << "\n"
              << "Index Encryption Compression CRC32    Uncompressed  Packed size Name\n"
                 "----- ---------- ----------- -------- ------------ ------------ ----------------\n";

    const auto flagsBefore =
        std::cout.setf(std::ios::right | std::ios::dec, std::ios::adjustfield | std::ios::basefield);
    const auto fillBefore = std::cout.fill(' ');

    auto index = std::size_t{};
    for (const auto& entry : archive)
    {
        // clang-format off
        std::cout << std::setw(5) << index++ << ' '

                  << std::left
                  << std::setw(10) << getEncryptionDescription(entry.encryption) << ' '
                  << std::setw(11) << getCompressionDescription(entry.compression) << ' '
                  << std::right

                  << std::setfill('0') << std::hex
                  << std::setw(8) << entry.crc32 << ' '
                  << std::setfill(' ') << std::dec

                  << std::setw(12) << entry.uncompressedSize << ' '
                  << std::setw(12) << entry.packedSize << ' '
                  << entry.name << '\n';
        // clang-format on
    }

    std::cout.fill(fillBefore);
    std::cout.flags(flagsBefore);
}

} // namespace
