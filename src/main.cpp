#include <cstdlib>
#include <iostream>
#include <iomanip>

#include "log.hpp"
#include "file.hpp"
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
                      in hexadecimal (requires -d)

Optional:
 -C encryptedzip    Zip archive containing cipherfile
 -P plainzip        Zip archive containing plainfile
 -o offset          Known plaintext offset relative to ciphertext
                      without encryption header (may be negative)
 -t size            Maximum number of bytes of plaintext to read
 -x offset data     Additional plaintext in hexadecimal starting
                      at the given offset (may be negative)
 -e                 Exhaustively try all the keys remaining after Z reduction
 -d decipheredfile  File to write the deciphered text
 -h                 Show this help and exit)_";

int main(int argc, char const *argv[])
{
    // setup output stream
    std::cout << std::fixed << std::setprecision(1);

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
        dwordvec::const_iterator zbegin = zr.begin(), zend = zr.end();
        std::size_t size = std::distance(zbegin, zend);
        std::size_t done = 0;

        std::cout << "[" << put_time << "] Attack on " << size << " Z values at index "
                  << (static_cast<int>(data.offset + zr.getIndex()) - static_cast<int>(Data::ENCRYPTION_HEADER_SIZE)) << std::endl;
        Attack attack(data, zr.getIndex());

        const bool canStop = !args.exhaustive;
        bool shouldStop = false;

        #pragma omp parallel for firstprivate(attack) schedule(dynamic)
        for(dwordvec::const_iterator it = zbegin; it < zend; ++it)
        {
            if(shouldStop)
                continue; // can not break out of an OpenMP for loop

            if(attack.carryout(*it))
            #pragma omp critical
            {
                Keys possibleKeys = attack.getKeys();
                keysvec.push_back(possibleKeys);

                if(canStop)
                    shouldStop = true;
                else
                    std::cout << "Keys: " << possibleKeys << std::endl;
            }

            #pragma omp critical
            std::cout << progress(++done, size) << std::flush << "\r";
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
        Keys keys = keysvec.front();
        if(keysvec.size() > 1)
            std::cout << "Deciphering data using the keys " << keys << "\n"
                      << "Use the command line option -k to provide other keys." << std::endl;

        std::ifstream cipherstream;
        std::size_t ciphersize = std::numeric_limits<std::size_t>::max();
        std::ofstream decipheredstream;

        try
        {
            // fstreams are swapped instead of move-assigned to avoid
            // a bug in some old versions of GCC (see issue #4 on github)

            if(args.cipherarchive.empty())
            {
                std::ifstream stream = openInput(args.cipherfile);
                cipherstream.swap(stream);
            }
            else
            {
                std::ifstream stream = openInputZipEntry(args.cipherarchive, args.cipherfile, ciphersize);
                cipherstream.swap(stream);
            }

            std::ofstream stream = openOutput(args.decipheredfile);
            decipheredstream.swap(stream);
        }
        catch(const FileError& e)
        {
            std::cout << e.what() << std::endl;
            return 1;
        }

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

        std::cout << "Wrote deciphered text." << std::endl;
    }

    return 0;
}
