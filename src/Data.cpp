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

    // copy extra plaintext and shift offsets to absolute values
    std::transform(args.extraPlaintext.begin(), args.extraPlaintext.end(),
        std::back_inserter(extraPlaintext),
        [](const std::pair<int, byte>& extra)
        {
            return std::make_pair(ENCRYPTION_HEADER_SIZE + extra.first, extra.second);
        });

    offset = ENCRYPTION_HEADER_SIZE + args.offset;

    // merge extra plaintext with contiguous plaintext if possible
    auto before = std::lower_bound(extraPlaintext.begin(), extraPlaintext.end(), std::make_pair(offset, byte()));
    auto after = std::lower_bound(before, extraPlaintext.end(), std::make_pair(offset + plaintext.size(), byte()));

    std::for_each(before, after,
        [this](const std::pair<std::size_t, byte>& a)
        {
            plaintext[a.first - offset] = a.second;
        });

    while(before != extraPlaintext.begin() && (before - 1)->first == offset - 1)
    {
        plaintext.insert(plaintext.begin(), (--before)->second);
        offset--;
    }

    while(after != extraPlaintext.end() && after->first == offset + plaintext.size())
    {
        plaintext.push_back(after->second);
        after++;
    }

    after = extraPlaintext.erase(before, after);

    // reorder remaining extra plaintext for filtering
    std::reverse(extraPlaintext.begin(), after);
    std::inplace_merge(extraPlaintext.begin(), after, extraPlaintext.end(),
        [this](const std::pair<std::size_t, byte>& a, const std::pair<std::size_t, byte>& b)
        {
            return absdiff(a.first, offset + Attack::CONTIGUOUS_SIZE) < absdiff(b.first, offset + Attack::CONTIGUOUS_SIZE);
        });

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
