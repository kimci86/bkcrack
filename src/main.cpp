#include "VirtualTerminalSupport.hpp"
#include "log.hpp"
#include "ConsoleProgress.hpp"
#include "file.hpp"
#include "zip.hpp"
#include "Arguments.hpp"
#include "Data.hpp"
#include "Zreduction.hpp"
#include "Attack.hpp"
#include "password.hpp"
#include "version.hpp"
#include <cassert>
#include <iomanip>
#include <limits>

namespace
{

const char* usage = R"_(usage: bkcrack [options]
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

 -e, --exhaustive            Try all the keys remaining after Z reduction

Options to use the internal password representation:
 -k, --keys <X> <Y> <Z>      Internal password representation as three 32-bits
                              integers in hexadecimal (requires -d, -U or -r)

 -d, --decipher <file>       File to write the deciphered data (requires -c)

 -U, --change-password <archive> <password>
        Create a copy of the encrypted zip archive with the password set to the
        given new password (requires -C)

 -r, --recover-password <length> <charset>
        Try to recover the password or an equivalent one up to the given length
        using characters in the given charset. The charset is a sequence of
        characters or shortcuts for predefined charsets listed below.
        Example: ?l?d-.@
          ?l lowercase letters
          ?u uppercase letters
          ?d decimal digits
          ?s punctuation
          ?a alpha-numerical characters (same as ?l?u?d)
          ?p printable characters (same as ?a?s)
          ?b all bytes (0x00 - 0xff)

Other options:
 -L, --list <archive>        List entries in a zip archive and exit
 -h, --help                  Show this help and exit

Environment variables:
 OMP_NUM_THREADS             Number of threads to use for parallel computations)_";

void listEntries(const std::string& archive);

} // namespace

int main(int argc, char const *argv[])
try
{
    // enable virtual terminal support on Windows, no-op on other platforms
    VirtualTerminalSupport vtSupport;

    // version information
    std::cout << "bkcrack " BKCRACK_VERSION " - " BKCRACK_COMPILATION_DATE << std::endl;

    const Arguments args(argc, argv);
    if(args.help)
    {
        std::cout << usage << std::endl;
        return 0;
    }

    if(args.infoArchive)
    {
        listEntries(*args.infoArchive);
        return 0;
    }

    std::vector<Keys> keysvec;
    if(args.keys)
        keysvec.push_back(*args.keys);
    else
    // find keys from known plaintext
    {
        const Data data = args.loadData();

        // generate and reduce Zi[10,32) values
        Zreduction zr(data.keystream);
        if(data.keystream.size() > Attack::CONTIGUOUS_SIZE)
        {
            std::cout << "[" << put_time << "] Z reduction using " << (data.keystream.size() - Attack::CONTIGUOUS_SIZE) << " bytes of known plaintext" << std::endl;

            ConsoleProgress progress(std::cout);
            zr.reduce(progress);
        }

        // generate Zi[2,32) values
        zr.generate();

        // carry out the attack on the remaining Zi[2,32) values
        std::cout << "[" << put_time << "] Attack on " << zr.getCandidates().size() << " Z values at index "
                  << (static_cast<int>(data.offset + zr.getIndex()) - static_cast<int>(Data::ENCRYPTION_HEADER_SIZE)) << std::endl;

        {
            ConsoleProgress progress(std::cout);
            keysvec = attack(data, zr.getCandidates(), zr.getIndex(), args.exhaustive, progress);
        }

        // print the keys
        std::cout << "[" << put_time << "] ";
        if(keysvec.empty())
        {
            std::cout << "Could not find the keys." << std::endl;
            return 1;
        }
        else
        {
            std::cout << "Keys" << std::endl;
            for(const Keys& keys : keysvec)
                std::cout << keys << std::endl;
        }
    }

    // From there, keysvec is not empty.

    // decipher
    if(args.decipheredFile)
    {
        std::cout << "[" << put_time << "] Writing deciphered data " << *args.decipheredFile << " (maybe compressed)"<< std::endl;

        Keys keys = keysvec.front();
        if(keysvec.size() > 1)
            std::cout << "Deciphering data using the keys " << keys << "\n"
                      << "Use the command line option -k to provide other keys." << std::endl;

        {
            auto [cipherstream, ciphersize] =
                args.cipherArchive
                    ? args.cipherFile
                        ? openZipEntry(*args.cipherArchive, *args.cipherFile, ZipEntry::Encryption::Traditional)
                        : openZipEntry(*args.cipherArchive, *args.cipherIndex, ZipEntry::Encryption::Traditional)
                    : std::pair{openInput(*args.cipherFile), std::numeric_limits<std::size_t>::max()};

            std::ofstream decipheredstream = openOutput(*args.decipheredFile);

            decipher(cipherstream, ciphersize, Data::ENCRYPTION_HEADER_SIZE, decipheredstream, keys);
        }

        std::cout << "Wrote deciphered data." << std::endl;
    }

    // unlock
    if(args.changePassword)
    {
        const auto& [unlockedArchive, newPassword] = *args.changePassword;

        std::cout << "[" << put_time << "] Writing unlocked archive " << unlockedArchive << " with password \"" << newPassword << "\"" << std::endl;

        Keys keys = keysvec.front();
        if(keysvec.size() > 1)
            std::cout << "Unlocking archive using the keys " << keys << "\n"
                      << "Use the command line option -k to provide other keys." << std::endl;

        {
            std::ifstream encrypted = openInput(*args.cipherArchive);
            std::ofstream unlocked = openOutput(unlockedArchive);

            ConsoleProgress progress(std::cout);
            changeKeys(encrypted, unlocked, keys, Keys(newPassword), progress);
        }

        std::cout << "Wrote unlocked archive." << std::endl;
    }

    // recover password
    if(args.recoverPassword)
    {
        const auto& [maxLength, charset] = *args.recoverPassword;

        std::cout << "[" << put_time << "] Recovering password" << std::endl;
        std::string password;
        bool success;

        {
            ConsoleProgress progress(std::cout);
            success = recoverPassword(keysvec.front(), maxLength, charset, password, progress);
        }

        if(success)
        {
            std::cout << "[" << put_time << "] Password" << std::endl;
            std::cout << "as bytes: ";
            {
                const auto flagsBefore = std::cout.setf(std::ios::hex, std::ios::basefield);
                const auto fillBefore = std::cout.fill('0');

                for(byte c : password)
                    std::cout << std::setw(2) << static_cast<int>(c) << ' ';
                std::cout << std::endl;

                std::cout.fill(fillBefore);
                std::cout.flags(flagsBefore);
            }
            std::cout << "as text: " << password << std::endl;
        }
        else
        {
            std::cout << "[" << put_time << "] Could not recover password" << std::endl;
            return 1;
        }
    }

    return 0;
}
catch(const Arguments::Error& e)
{
    std::cout << e.what() << std::endl;
    std::cout << "Run 'bkcrack -h' for help." << std::endl;
    return 1;
}
catch(const BaseError& e)
{
    std::cout << e.what() << std::endl;
    return 1;
}

namespace
{

std::string getEncryptionDescription(ZipEntry::Encryption encryption)
{
    switch(encryption)
    {
        case ZipEntry::Encryption::None:        return "None";
        case ZipEntry::Encryption::Traditional: return "ZipCrypto";
        case ZipEntry::Encryption::Unsupported: return "Other";
    }
    assert(false);

    return "";
}

std::string getCompressionDescription(ZipEntry::Compression compression)
{
    switch(compression)
    {
        #define CASE(c) case ZipEntry::Compression::c: return #c
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

void listEntries(const std::string& archive)
{
    std::ifstream is = openInput(archive);
    auto it = locateZipEntries(is);

    std::cout << "Archive: " << archive << "\n"
                 "Index Encryption Compression CRC32    Uncompressed  Packed size Name\n"
                 "----- ---------- ----------- -------- ------------ ------------ ----------------\n";

    const auto flagsBefore = std::cout.setf(std::ios::right | std::ios::dec, std::ios::adjustfield | std::ios::basefield);
    const auto fillBefore = std::cout.fill(' ');

    for(std::size_t index = 0; it != ZipIterator(); ++it, index++)
    {
        std::cout << std::setw(5) << index << ' '

                  << std::left
                  << std::setw(10) << getEncryptionDescription(it->encryption) << ' '
                  << std::setw(11) << getCompressionDescription(it->compression) << ' '
                  << std::right

                  << std::setfill('0') << std::hex
                  << std::setw(8) << it->crc32 << ' '
                  << std::setfill(' ') << std::dec

                  << std::setw(12) << it->uncompressedSize << ' '
                  << std::setw(12) << it->packedSize << ' '
                  << it->name << '\n';
    }

    std::cout.fill(fillBefore);
    std::cout.flags(flagsBefore);
}

} // namespace
