#include "log.hpp"
#include "file.hpp"
#include "zip.hpp"
#include "Arguments.hpp"
#include "Data.hpp"
#include "Zreduction.hpp"
#include "Attack.hpp"
#include "KeystreamTab.hpp"

const char* usage = R"_(usage: bkcrack [options]
Crack legacy zip encryption with Biham and Kocher's known plaintext attack.

Mandatory:
 -c cipherfile      File containing the ciphertext
 -p plainfile       File containing the known plaintext

    or

 -k X Y Z           Internal password representation as three 32-bits integers
                      in hexadecimal (requires -d or -U)

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

 -h                 Show this help and exit)_";

int main(int argc, char const *argv[])
{
    // setup output stream
    std::cout << setupLog << std::endl;

    // parse arguments
    Arguments args;
    try
    {
        args.parse(argc, argv);
    }
    catch(const Arguments::Error& e)
    {
        std::cout << e.what() << std::endl;
        std::cout << "Run 'bkcrack -h' for help." << std::endl;
        return 1;
    }

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
        // load data
        Data data;
        try
        {
            data.load(args);
        }
        catch(const BaseError& e)
        {
            std::cout << e.what() << std::endl;
            return 1;
        }

        // generate and reduce Zi[2,32) values
        Zreduction zr(data.keystream);
        zr.generate();
        std::cout << "Generated " << zr.size() << " Z values." << std::endl;

        if(data.keystream.size() > Attack::CONTIGUOUS_SIZE)
        {
            std::cout << "[" << put_time << "] Z reduction using " << (data.keystream.size() - Attack::CONTIGUOUS_SIZE) << " bytes of known plaintext" << std::endl;
            zr.reduce();
            std::cout << zr.size() << " values remaining." << std::endl;
        }

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
            std::cout << "Could not find the keys." << std::endl;
        else
        {
            std::cout << "Keys" << std::endl;
            for(const Keys& keys : keysvec)
                std::cout << keys << std::endl;
        }
    }

    // decipher
    if(!keysvec.empty() && !args.decipheredfile.empty())
    {
        std::cout << "[" << put_time << "] Writing deciphered data " << args.decipheredfile << " (maybe compressed)"<< std::endl;

        Keys keys = keysvec.front();
        if(keysvec.size() > 1)
            std::cout << "Deciphering data using the keys " << keys << "\n"
                      << "Use the command line option -k to provide other keys." << std::endl;

        try
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
        catch(const BaseError& e)
        {
            std::cout << e.what() << std::endl;
            return 1;
        }

        std::cout << "Wrote deciphered data." << std::endl;
    }

    // unlock
    if(!keysvec.empty() && !args.unlockedarchive.empty())
    {
        std::cout << "[" << put_time << "] Writing unlocked archive " << args.unlockedarchive << " with password \"" << args.newPassword << "\"" << std::endl;

        Keys keys = keysvec.front();
        if(keysvec.size() > 1)
            std::cout << "Unlocking archive using the keys " << keys << "\n"
                      << "Use the command line option -k to provide other keys." << std::endl;

        try
        {
            std::ifstream encrypted = openInput(args.cipherarchive);
            std::ofstream unlocked = openOutput(args.unlockedarchive);

            changeKeys(encrypted, unlocked, keys, Keys(args.newPassword));
        }
        catch(const BaseError& e)
        {
            std::cout << e.what() << std::endl;
            return 1;
        }

        std::cout << "Wrote unlocked archive." << std::endl;
    }

    return 0;
}
