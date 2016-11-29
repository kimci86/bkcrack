#include <cstdlib>
#include <iostream>
#include <iomanip>

#include "log.hpp"
#include "file.hpp"
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
 -d decipheredfile  File to write the deciphered text
 -b begin           Beginning index of the selected slice of key space
 -s size            Size of the selected slice of key space
 -h                 Show this help and exit)_";

int main(int argc, char const *argv[])
{
    // setup output stream
    std::cout << std::fixed << std::setprecision(1);

    // parse arguments
    std::string cipherfile, cipherarchive,
                plainfile, plainarchive,
                decipheredfile;
    Data data;
    Keys keys;
    bool keysFound = false;
    std::size_t begin = 0, size = 1 << 22;
    bool slice = false;

    for(int i = 1; i < argc; i++)
    {
        std::string flag = argv[i];
        if(flag.size() == 2 && flag[0] == '-' && i+1 < argc)
        {
            std::string value = argv[++i];
            switch(flag[1])
            {
                case 'c':
                    cipherfile = value;
                    break;
                case 'p':
                    plainfile = value;
                    break;
                case 'C':
                    cipherarchive = value;
                    break;
                case 'P':
                    plainarchive = value;
                    break;
                case 'o':
                    data.offset = std::stoi(value);
                    break;
                case 'd':
                    decipheredfile = value;
                    break;
                case 'b':
                    begin = std::stoi(value);
                    slice = true;
                    break;
                case 's':
                    size = std::stoi(value);
                    slice = true;
                    break;
                case 'k':
                    if(i + 2 < argc)
                    {
                        dword x = std::stoul(argv[i],   nullptr, 16),
                              y = std::stoul(argv[++i], nullptr, 16),
                              z = std::stoul(argv[++i], nullptr, 16);
                        keys = Keys(x, y, z);
                        keysFound = true;
                    }
                    else
                    {
                        std::cout << usage << std::endl;
                        return 1;
                    }
                    break;
                case 'h':
                    std::cout << usage << std::endl;
                    return 0;
                default:
                    std::cout << usage << std::endl;
                    return 1;
            }
        }
        else
        {
            std::cout << usage << std::endl;
            return 1;
        }
    }

    // check mandatory arguments
    if(cipherfile.empty() || plainfile.empty() && !keysFound || decipheredfile.empty() && keysFound)
    {
        std::cout << usage << std::endl;
        return 1;
    }

    // find keys from known plaintext
    if(!keysFound)
    {
        // load data
        try
        {
            data.load(cipherarchive, cipherfile, plainarchive, plainfile);
        }
        catch(FileError e)
        {
            std::cout << "file error: " << e.what() << std::endl;
            return 1;
        }
        catch(Data::Error e)
        {
            std::cout << "invalid data: " << e.what() << std::endl;
            return 1;
        }

        // generate and reduce Zi[2,32) values
        Zreduction zr(data.keystream);
        zr.generate();
        std::cout << "Generated " << zr.size() << " Z values." << std::endl;

        if(data.keystream.size() > Attack::size)
        {
            std::cout << "[" << put_time << "] Z reduction using " << (data.keystream.size() - Attack::size) << " extra bytes of known plaintext" << std::endl;
            zr.reduce();
            std::cout << zr.size() << " values remaining." << std::endl;
        }

        // keep only the selected slice of Zi[2,32) values
        dwordvec::const_iterator zbegin = zr.begin(), zend = zr.end();
        if(slice)
        {
            if(0 <= begin && begin <= zr.size())
                zbegin += begin;
            if(0 <= size && begin + size <= zr.size())
                zend = zbegin + size;
            std::cout << "Keeping values from " << std::distance(zr.begin(), zbegin) << " to " << std::distance(zr.begin(), zend) << "." << std::endl;
        }
        size = std::distance(zbegin, zend);

        // iterate over remaining Zi[2,32) values
        std::cout << "[" << put_time << "] Attack on " << size << " Z values at index " << (data.offset + static_cast<int>(zr.getIndex())) << std::endl;
        std::size_t done = 0;
        Attack attack(data, zr.getIndex()-11);

        #pragma omp parallel for firstprivate(attack) schedule(dynamic)
        for(dwordvec::const_iterator it = zbegin; it < zend; ++it)
        {
            if(keysFound)
                continue;

            if(attack.carryout(*it))
            #pragma omp critical
            {
                keysFound = true;
                keys = attack.getKeys();
            }

            #pragma omp critical
            std::cout << progress(++done, size) << std::flush << "\r";
        }

        if(size)
            std::cout << std::endl;
    }

    // print the keys
    std::cout << "[" << put_time << "] ";
    if(keysFound)
        std::cout << "Keys" << std::endl
                  << std::hex << keys.getX() << " " << keys.getY() << " " << keys.getZ() << std::endl;
    else
        std::cout << "Could not find the keys." << std::endl;

    // decipher
    if(keysFound && !decipheredfile.empty())
    {
        std::ifstream cipherstream;
        std::size_t ciphersize = std::numeric_limits<std::size_t>::max();
        std::ofstream decipheredstream;

        try
        {
            if(cipherarchive.empty())
                cipherstream = openInput(cipherfile);
            else
                cipherstream = openInputZipEntry(cipherarchive, cipherfile, ciphersize);
            decipheredstream = openOutput(decipheredfile);
        }
        catch(FileError e)
        {
            std::cout << "file error: " << e.what() << std::endl;
            return 1;
        }

        // discard the encryption header
        std::istreambuf_iterator<char> cipher(cipherstream);
        std::size_t i;
        for(i = 0; i < Data::headerSize && cipher != std::istreambuf_iterator<char>(); i++, ++cipher)
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
