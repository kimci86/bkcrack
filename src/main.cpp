#include "VirtualTerminalSupport.hpp"
#include "log.hpp"
#include "ConsoleProgress.hpp"
#include "file.hpp"
#include "Zip.hpp"
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
     --ignore-check-byte     Do not automatically use ciphertext's check byte
                              as known plaintext

 -e, --exhaustive            Try all the keys remaining after Z reduction

     --password <password>   Password from which to derive the internal password
                              representation. Useful for testing purposes and
                              advanced scenarios such as reverting the effect of
                              the --change-password command.

Options to use the internal password representation:
 -k, --keys <X> <Y> <Z>      Internal password representation as three 32-bits
                              integers in hexadecimal (requires -d, -U,
                              --change-keys or -r)

 -d, --decipher <file>       File to write the deciphered data (requires -c)
     --keep-header           Write the encryption header at the beginning of
                              deciphered data instead of discarding it

 -U, --change-password <archive> <password>
        Create a copy of the encrypted zip archive with the password set to the
        given new password (requires -C)

     --change-keys <archive> <X> <Y> <Z>
        Create a copy of the encrypted zip archive using the given new internal
        password representation (requires -C)

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

void listEntries(const std::string& archiveFilename);
void decipher(std::istream& is, std::size_t size, std::size_t discard, std::ostream& os, Keys keys);

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
    else if(args.password)
    {
        keysvec.emplace_back(*args.password);
        std::cout << "Internal representation for password \"" << *args.password << "\": " << keysvec.back() << std::endl;
    }
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

    const Keys keys = keysvec.front();
    if((args.decipheredFile || args.changePassword || args.changeKeys || args.recoverPassword) && keysvec.size() > 1)
        std::cout << "Continuing with keys " << keys << "\n"
                  << "Use the command line option -k to provide other keys." << std::endl;

    // decipher
    if(args.decipheredFile)
    {
        std::cout << "[" << put_time << "] Writing deciphered data " << *args.decipheredFile << " (maybe compressed)";
        if(args.keepHeader)
            std::cout << " with encryption header";
        std::cout << std::endl;

        {
            std::ifstream cipherstream = openInput(args.cipherArchive ? *args.cipherArchive : *args.cipherFile);
            std::size_t ciphersize = std::numeric_limits<std::size_t>::max();

            if(args.cipherArchive)
            {
                const auto archive = Zip{cipherstream};
                const auto entry = args.cipherFile ? archive[*args.cipherFile] : archive[*args.cipherIndex];
                Zip::checkEncryption(entry, Zip::Encryption::Traditional);

                archive.seek(entry);
                ciphersize = entry.packedSize;
            }

            std::ofstream decipheredstream = openOutput(*args.decipheredFile);

            decipher(cipherstream, ciphersize, args.keepHeader ? 0 : static_cast<std::size_t>(Data::ENCRYPTION_HEADER_SIZE), decipheredstream, keys);
        }

        std::cout << "Wrote deciphered data." << std::endl;
    }

    // unlock
    if(args.changePassword)
    {
        const auto& [unlockedArchive, newPassword] = *args.changePassword;

        std::cout << "[" << put_time << "] Writing unlocked archive " << unlockedArchive << " with password \"" << newPassword << "\"" << std::endl;

        {
            const auto archive = Zip{*args.cipherArchive};
            std::ofstream unlocked = openOutput(unlockedArchive);

            ConsoleProgress progress(std::cout);
            archive.changeKeys(unlocked, keys, Keys{newPassword}, progress);
        }

        std::cout << "Wrote unlocked archive." << std::endl;
    }

    if(args.changeKeys)
    {
        const auto& [unlockedArchive, newKeys] = *args.changeKeys;

        std::cout << "[" << put_time << "] Writing unlocked archive " << unlockedArchive << " with keys " << newKeys << std::endl;

        {
            const auto archive = Zip{*args.cipherArchive};
            std::ofstream unlocked = openOutput(unlockedArchive);

            ConsoleProgress progress(std::cout);
            archive.changeKeys(unlocked, keys, newKeys, progress);
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

std::string getEncryptionDescription(Zip::Encryption encryption)
{
    switch(encryption)
    {
        case Zip::Encryption::None:        return "None";
        case Zip::Encryption::Traditional: return "ZipCrypto";
        case Zip::Encryption::Unsupported: return "Other";
    }
    assert(false);

    return "";
}

std::string getCompressionDescription(Zip::Compression compression)
{
    switch(compression)
    {
        #define CASE(c) case Zip::Compression::c: return #c
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
    auto archive = Zip{archiveFilename};

    std::cout << "Archive: " << archiveFilename << "\n"
                 "Index Encryption Compression CRC32    Uncompressed  Packed size Name\n"
                 "----- ---------- ----------- -------- ------------ ------------ ----------------\n";

    const auto flagsBefore = std::cout.setf(std::ios::right | std::ios::dec, std::ios::adjustfield | std::ios::basefield);
    const auto fillBefore = std::cout.fill(' ');

    std::size_t index = 0;
    for(const auto& entry : archive)
    {
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
    }

    std::cout.fill(fillBefore);
    std::cout.flags(flagsBefore);
}

void decipher(std::istream& is, std::size_t size, std::size_t discard, std::ostream& os, Keys keys)
{
    std::istreambuf_iterator<char> cipher(is);
    std::size_t i;

    for(i = 0; i < discard && i < size && cipher != std::istreambuf_iterator<char>(); i++, ++cipher)
       keys.update(*cipher ^ keys.getK());

    for(std::ostreambuf_iterator<char> plain(os); i < size && cipher != std::istreambuf_iterator<char>(); i++, ++cipher, ++plain)
    {
        byte p = *cipher ^ keys.getK();
        keys.update(p);
        *plain = p;
    }
}

} // namespace
