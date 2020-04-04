#include "Data.hpp"
#include "file.hpp"
#include "Attack.hpp"
#include <algorithm>
#include <functional>
#include <iterator>

Data::Error::Error(const std::string& description)
 : BaseError("Data error", description)
{}

void Data::load(const std::string& cipherarchive, const std::string& cipherfile,
                const std::string& plainarchive, const std::string& plainfile, std::size_t plainsize)
{
    // check that offset is not too small
    if(headerSize + offset < 0)
        throw Error("offset is too small");

    // load known plaintext
    if(plainarchive.empty())
        plaintext = loadFile(plainfile, plainsize);
    else
        plaintext = loadZipEntry(plainarchive, plainfile, plainsize);

    // check that plaintext is big enough
    if(plaintext.size() < Attack::size)
        throw Error("plaintext is too small");

    // load ciphertext needed by the attack
    std::size_t toRead = headerSize + offset + plaintext.size();
    if(cipherarchive.empty())
        ciphertext = loadFile(cipherfile, toRead);
    else
        ciphertext = loadZipEntry(cipherarchive, cipherfile, toRead);

    // check that ciphertext is valid
    if(plaintext.size() > ciphertext.size())
        throw Error("ciphertext is smaller than plaintext");
    else if(headerSize + offset + plaintext.size() > ciphertext.size())
        throw Error("offset is too large");

    // compute keystream
    std::transform(plaintext.begin(), plaintext.end(),
                   ciphertext.begin() + headerSize + offset,
                   std::back_inserter(keystream), std::bit_xor<byte>());
}
