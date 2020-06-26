#include "Data.hpp"
#include "file.hpp"
#include "Attack.hpp"
#include <algorithm>
#include <functional>
#include <iterator>

Data::Error::Error(const std::string& description)
 : BaseError("Data error", description)
{}

void Data::load(const Arguments& args)
{
    // load known plaintext
    if(args.plainarchive.empty())
        plaintext = loadFile(args.plainfile, args.plainsize);
    else
        plaintext = loadZipEntry(args.plainarchive, args.plainfile, args.plainsize);

    // TODO
    // - extend contiguous plaintext with extra plaintext if possible, emit warning on overlap
    // - sort extra plaintext for better filtering performance

    // copy extra plaintext and shift offsets to absolute values
    std::transform(args.extraPlaintext.begin(), args.extraPlaintext.end(),
        std::back_inserter(extraPlaintext),
        [](const std::pair<int, byte>& extra)
        {
            return std::make_pair(ENCRYPTION_HEADER_SIZE + extra.first, extra.second);
        });

    offset = ENCRYPTION_HEADER_SIZE + args.offset;

    // check that there is enough known plaintext
    if(plaintext.size() < Attack::CONTIGUOUS_SIZE)
        throw Error("contiguous plaintext is too small");
    if(plaintext.size() + extraPlaintext.size() < Attack::ATTACK_SIZE)
        throw Error("plaintext is too small");

    // load ciphertext needed by the attack
    std::size_t toRead = offset + plaintext.size();
    if(!extraPlaintext.empty())
        toRead = std::max(toRead, extraPlaintext.back().first + 1);

    if(args.cipherarchive.empty())
        ciphertext = loadFile(args.cipherfile, toRead);
    else
        ciphertext = loadZipEntry(args.cipherarchive, args.cipherfile, toRead);

    // check that ciphertext's size is valid
    if(ciphertext.size() < plaintext.size())
        throw Error("ciphertext is smaller than plaintext");
    else if(ciphertext.size() < offset + plaintext.size())
        throw Error("plaintext offset is too large");
    else if(ciphertext.size() < toRead)
        throw Error("extra plaintext offset is too large");

    // compute keystream
    std::transform(plaintext.begin(), plaintext.end(),
                   ciphertext.begin() + offset,
                   std::back_inserter(keystream), std::bit_xor<byte>());
}
