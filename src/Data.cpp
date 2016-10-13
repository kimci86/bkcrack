#include "Data.hpp"
#include "file.hpp"
#include "Attack.hpp"
#include <algorithm>
#include <functional>
#include <iterator>

Data::Error::Error(const std::string& description)
 : std::logic_error(description)
{}

void Data::load(const std::string& cipherfile, const std::string& plainfile)
{
    // check that offset is not too small
    if(headerSize + offset < 0)
        throw Error("offset is too small");

    // load known plaintext
    {
        std::ifstream plainstream = openInput(plainfile);
        plaintext.assign(std::istreambuf_iterator<char>(plainstream),
                         std::istreambuf_iterator<char>());
    }

    // check that plaintext is big enough
    if(plaintext.size() < Attack::size)
        throw Error("plaintext is too small");

    // load ciphertext needed by the attack
    {
        std::ifstream cipherstream = openInput(cipherfile);
        std::istreambuf_iterator<char> it(cipherstream);

        std::size_t toRead = headerSize + offset + plaintext.size();
        // read at most toRead bytes
        for(std::size_t i = 0; i < toRead && it != std::istreambuf_iterator<char>(); i++, ++it)
            ciphertext.push_back(*it);
    }

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
