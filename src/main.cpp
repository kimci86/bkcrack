#include "log.hpp"
#include "file.hpp"
#include "zip.hpp"
#include "Arguments.hpp"
#include "Data.hpp"
#include "Zreduction.hpp"
#include "Attack.hpp"
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

 -e                 Exhaustively look for all solutions (keys or passwords)
                      instead of stopping after the first solution is found

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

 -s value           Starting point of the password recovery

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

            ProgressPrinter printer(std::cout);
            zr.reduce(&printer.progress);
        }

        // generate Zi[2,32) values
        zr.generate();

        // carry out the attack on the remaining Zi[2,32) values
        std::cout << "[" << put_time << "] Attack on " << zr.getCandidates().size() << " Z values at index "
                  << (static_cast<int>(data.offset + zr.getIndex()) - static_cast<int>(Data::ENCRYPTION_HEADER_SIZE)) << std::endl;

        {
            ProgressPrinter printer(std::cout);
            keysvec = attack(data, zr.getCandidates(), zr.getIndex(), args.exhaustive, &printer.progress);
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

            decipher(cipherstream, ciphersize, Data::ENCRYPTION_HEADER_SIZE, decipheredstream, keys);
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

            ProgressPrinter printer(std::cout);
            changeKeys(encrypted, unlocked, keys, Keys(args.newPassword), &printer.progress);
        }

        std::cout << "Wrote unlocked archive." << std::endl;
    }

    // recover password
    if(args.maxLength)
    {
        std::cout << "[" << put_time << "] Recovering password" << std::endl;

        int start = args.start;
        std::vector<std::string> passwords;
        {
            ProgressPrinter printer(std::cout);
            passwords = recoverPassword(keysvec.front(), args.charset, 0, args.maxLength, start, args.exhaustive, &printer.progress);
        }

        std::cout << "[" << put_time << "] ";
        if(passwords.empty())
        {
            std::cout << "Could not recover password" << std::endl;
            if(start != std::numeric_limits<int>::max())
                std::cout << "You can continue searching with options '-s " << start << "'" << std::endl;
            return 1;
        }
        else
        {
            std::cout << "Password" << std::endl;
            for(const std::string& password : passwords)
            {
                std::cout << "as bytes: ";
                std::cout << std::hex;
                for(byte c : password)
                    std::cout << static_cast<int>(c) << ' ';
                std::cout << std::dec << std::endl;
                std::cout << "as text: " << password << std::endl;
            }

            if(start != std::numeric_limits<int>::max())
                std::cout << "You can continue searching with options '-e -s " << start << "'" << std::endl;
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
