#include "log.hpp"
#include "file.hpp"
#include "zip.hpp"
#include "Arguments.hpp"
#include "Data.hpp"
#include "Zreduction.hpp"
#include "Attack.hpp"
#include "KeystreamTab.hpp"
#include "password.hpp"
#include <limits>

const char* usage = R"_(usage: bkcrack [options]
Crack legacy zip encryption with Biham and Kocher's known plaintext attack.

Mandatory:
 -c cipherfile      File containing the ciphertext
 -p plainfile       File containing the known plaintext

    or

 -k X Y Z           Internal password representation as three 32-bits integers
                      in hexadecimal (requires -d, -U, or -r)

Optional:
 -C encryptedzip    Zip archive containing cipherfile

 -P plainzip        Zip archive containing plainfile
 -o offset          Known plaintext offset relative to ciphertext
                      without encryption header (may be negative)
 -t size            Maximum number of bytes of plaintext to read
 -x offset data     Additional plaintext in hexadecimal starting
                      at the given offset (may be negative)

 -e                 Exhaustively try all the keys remaining after Z reduction

 -d decipheredfile  File to write the deciphered text (requires -c)
 -U unlockedzip password
                    File to write the encryped zip with the password set
                      to the given new password (requires -C)

 -r length charset  Try to recover the password up to the given length using
                      characters in the given charset. The charset is a
                      sequence of characters or shorcuts for predefined
                      charsets listed below. Example: ?l?d-.@

                      ?l lowercase letters
                      ?u uppercase letters
                      ?d decimal digits
                      ?s punctuation
                      ?a alpha-numerical characters (same as ?l?u?d)
                      ?p printable characters (same as ?a?s)
                      ?b all bytes (0x00 - 0xff)

 -h                 Show this help and exit)_";

int main(int argc, char const *argv[])
try
{
    // setup output stream
    std::cout << setupLog << std::endl;

    const Arguments args(argc, argv);
    if(args.help)
    {
        std::cout << usage << std::endl;
        return 0;
    }

    std::vector<Keys> keysvec;
    if(args.keysGiven)
        keysvec.push_back(args.keys);
    else
    // find keys from known plaintext
    {
        const Data data = args.loadData();

        // generate and reduce Zi[10,32) values
        Zreduction zr(data.keystream);
        if(data.keystream.size() > Attack::CONTIGUOUS_SIZE)
        {
            std::cout << "[" << put_time << "] Z reduction using " << (data.keystream.size() - Attack::CONTIGUOUS_SIZE) << " bytes of known plaintext" << std::endl;
            zr.reduce();
        }

        // generate Zi[2,32) values
        zr.generate();

        // iterate over remaining Zi[2,32) values
        const uint32* candidates = zr.data();
        const std::int32_t size = zr.size();
        std::int32_t done = 0;

        std::cout << "[" << put_time << "] Attack on " << size << " Z values at index "
                  << (static_cast<int>(data.offset + zr.getIndex()) - static_cast<int>(Data::ENCRYPTION_HEADER_SIZE)) << std::endl;
        Attack attack(data, zr.getIndex(), keysvec);

        const bool canStop = !args.exhaustive;
        bool shouldStop = false;

        #pragma omp parallel for firstprivate(attack) schedule(dynamic)
        for(std::int32_t i = 0; i < size; ++i) // OpenMP 2.0 requires signed index variable
        {
            if(shouldStop)
                continue; // cannot break out of an OpenMP for loop

            attack.carryout(candidates[i]);

            #pragma omp critical
            {
                std::cout << progress(++done, size) << std::flush << "\r";
                shouldStop = canStop && !keysvec.empty();
            }
        }

        if(size)
            std::cout << std::endl;

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
    if(!args.decipheredfile.empty())
    {
        std::cout << "[" << put_time << "] Writing deciphered data " << args.decipheredfile << " (maybe compressed)"<< std::endl;

        Keys keys = keysvec.front();
        if(keysvec.size() > 1)
            std::cout << "Deciphering data using the keys " << keys << "\n"
                      << "Use the command line option -k to provide other keys." << std::endl;

        {
            std::size_t ciphersize = std::numeric_limits<std::size_t>::max();
            std::ifstream cipherstream = args.cipherarchive.empty() ? openInput(args.cipherfile) : openZipEntry(args.cipherarchive, args.cipherfile, ZipEntry::Encryption::Traditional, ciphersize);
            std::ofstream decipheredstream = openOutput(args.decipheredfile);

            // discard the encryption header
            std::istreambuf_iterator<char> cipher(cipherstream);
            std::size_t i;
            for(i = 0; i < Data::ENCRYPTION_HEADER_SIZE && cipher != std::istreambuf_iterator<char>(); i++, ++cipher)
                keys.update(*cipher ^ KeystreamTab::getByte(keys.getZ()));

            for(std::ostreambuf_iterator<char> plain(decipheredstream); i < ciphersize && cipher != std::istreambuf_iterator<char>(); i++, ++cipher, ++plain)
            {
                byte p = *cipher ^ KeystreamTab::getByte(keys.getZ());
                keys.update(p);
                *plain = p;
            }
        }

        std::cout << "Wrote deciphered data." << std::endl;
    }

    // unlock
    if(!args.unlockedarchive.empty())
    {
        std::cout << "[" << put_time << "] Writing unlocked archive " << args.unlockedarchive << " with password \"" << args.newPassword << "\"" << std::endl;

        Keys keys = keysvec.front();
        if(keysvec.size() > 1)
            std::cout << "Unlocking archive using the keys " << keys << "\n"
                      << "Use the command line option -k to provide other keys." << std::endl;

        {
            std::ifstream encrypted = openInput(args.cipherarchive);
            std::ofstream unlocked = openOutput(args.unlockedarchive);

            changeKeys(encrypted, unlocked, keys, Keys(args.newPassword));
        }

        std::cout << "Wrote unlocked archive." << std::endl;
    }

    // recover password
    if(args.maxLength)
    {
        std::cout << "[" << put_time << "] Recovering password" << std::endl;
        std::string password;
        if(recoverPassword(keysvec.front(), args.maxLength, args.charset, password))
        {
            std::cout << "[" << put_time << "] Password" << std::endl;
            std::cout << "as bytes: ";
            std::cout << std::hex;
            for(byte c : password)
                std::cout << static_cast<int>(c) << ' ';
            std::cout << std::dec << std::endl;
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
