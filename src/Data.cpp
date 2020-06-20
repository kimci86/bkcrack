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
    if(ENCRYPTION_HEADER_SIZE + offset < 0)
        throw Error("offset is too small");

    // load known plaintext
    if(plainarchive.empty())
        plaintext = loadFile(plainfile, plainsize);
    else
        plaintext = loadZipEntry(plainarchive, plainfile, plainsize);

    // check that plaintext is big enough
    if(plaintext.size() < Attack::CONTIGUOUS_SIZE)
        throw Error("contiguous plaintext is too small");
    if(plaintext.size() + extraPlaintext.size() < Attack::ATTACK_SIZE)
        throw Error("plaintext is too small");

    // load ciphertext needed by the attack
    std::size_t toRead = ENCRYPTION_HEADER_SIZE + offset + plaintext.size();
    if(!extraPlaintext.empty())
    {
        const int maxOffset = std::max_element(extraPlaintext.begin(), extraPlaintext.end(),
            [](const std::pair<int, byte>& a, const std::pair<int, byte>& b) { return a.first < b.first; }
            )->first;
        toRead = std::max(toRead, ENCRYPTION_HEADER_SIZE + maxOffset + 1);
    }
    if(cipherarchive.empty())
        ciphertext = loadFile(cipherfile, toRead);
    else
        ciphertext = loadZipEntry(cipherarchive, cipherfile, toRead);

    // check that ciphertext is valid
    if(plaintext.size() > ciphertext.size())
        throw Error("ciphertext is smaller than plaintext");
    else if(toRead > ciphertext.size())
        throw Error("offset is too large");

    // compute keystream
    std::transform(plaintext.begin(), plaintext.end(),
                   ciphertext.begin() + ENCRYPTION_HEADER_SIZE + offset,
                   std::back_inserter(keystream), std::bit_xor<byte>());
}
