#include "Data.hpp"

#include "Attack.hpp"

#include <algorithm>
#include <functional>
#include <iterator>

namespace
{

struct Range
{
    std::size_t size() const
    {
        return std::distance(begin, end);
    }

    bool operator<(const Range& other) const
    {
        return size() < other.size();
    }

    std::vector<std::pair<std::size_t, byte>>::iterator begin, end;
};

} // namespace

Data::Error::Error(const std::string& description)
: BaseError("Data error", description)
{
}

Data::Data(bytevec ciphertextArg, bytevec plaintextArg, int offsetArg, const std::map<int, byte>& extraPlaintextArg)
: ciphertext(std::move(ciphertextArg))
, plaintext(std::move(plaintextArg))
{
    // validate lengths
    if (ciphertext.size() < Attack::ATTACK_SIZE)
        throw Error("ciphertext is too small for an attack (minimum length is " + std::to_string(Attack::ATTACK_SIZE) +
                    ")");
    if (ciphertext.size() < plaintext.size())
        throw Error("ciphertext is smaller than plaintext");

    // validate offsets
    constexpr int minimumOffset = -static_cast<int>(ENCRYPTION_HEADER_SIZE);
    if (offsetArg < minimumOffset)
        throw Error("plaintext offset " + std::to_string(offsetArg) + " is too small (minimum is " +
                    std::to_string(minimumOffset) + ")");
    if (ciphertext.size() < ENCRYPTION_HEADER_SIZE + offsetArg + plaintext.size())
        throw Error("plaintext offset " + std::to_string(offsetArg) + " is too large");

    if (!extraPlaintextArg.empty() && extraPlaintextArg.begin()->first < minimumOffset)
        throw Error("extra plaintext offset " + std::to_string(extraPlaintextArg.begin()->first) +
                    " is too small (minimum is " + std::to_string(minimumOffset) + ")");
    if (!extraPlaintextArg.empty() && ciphertext.size() <= ENCRYPTION_HEADER_SIZE + extraPlaintextArg.rbegin()->first)
        throw Error("extra plaintext offset " + std::to_string(extraPlaintextArg.rbegin()->first) + " is too large");

    // shift offsets to absolute values
    offset = ENCRYPTION_HEADER_SIZE + offsetArg;

    std::transform(extraPlaintextArg.begin(), extraPlaintextArg.end(), std::back_inserter(extraPlaintext),
                   [](const std::pair<int, byte>& extra)
                   { return std::make_pair(ENCRYPTION_HEADER_SIZE + extra.first, extra.second); });

    // merge contiguous plaintext with adjacent extra plaintext
    {
        // Split extra plaintext into three ranges:
        // - [extraPlaintext.begin(), before) before contiguous plaintext
        // - [before, after)                  overlapping contiguous plaintext
        // - [after, extraPlaintext.end())    after contiguous plaintext

        auto before = std::lower_bound(extraPlaintext.begin(), extraPlaintext.end(), std::make_pair(offset, byte()));
        auto after  = std::lower_bound(before, extraPlaintext.end(), std::make_pair(offset + plaintext.size(), byte()));

        // overwrite overlapping plaintext
        std::for_each(before, after,
                      [this](const std::pair<std::size_t, byte>& e) { plaintext[e.first - offset] = e.second; });

        // merge contiguous plaintext with extra plaintext immediately before
        while (before != extraPlaintext.begin() && (before - 1)->first == offset - 1)
        {
            plaintext.insert(plaintext.begin(), (--before)->second);
            offset--;
        }

        // merge contiguous plaintext with extra plaintext immediately after
        while (after != extraPlaintext.end() && after->first == offset + plaintext.size())
            plaintext.push_back((after++)->second);

        // discard merged extra plaintext
        extraPlaintext.erase(before, after);
    }

    // find the longest contiguous sequence in extra plaintext and use is as contiguous plaintext if sensible
    {
        Range range = {extraPlaintext.begin(), extraPlaintext.begin()}; // empty

        for (auto it = extraPlaintext.begin(); it != extraPlaintext.end();)
        {
            Range current = {it, ++it};
            while (it != extraPlaintext.end() && it->first == (current.end - 1)->first + 1)
                current.end = ++it;

            range = std::max(range, current);
        }

        if (plaintext.size() < range.size())
        {
            const std::size_t plaintextSize = plaintext.size();
            const std::size_t rangeOffset   = range.begin->first;

            // append last bytes from the range to contiguous plaintext
            for (std::size_t i = plaintextSize; i < range.size(); i++)
                plaintext.push_back(range.begin[i].second);

            // remove those bytes from the range
            range.end = extraPlaintext.erase(range.begin + plaintextSize, range.end);
            if (plaintextSize == 0)
                range.begin = range.end;

            // rotate extra plaintext so that it will be sorted at the end of this scope
            {
                auto before =
                    std::lower_bound(extraPlaintext.begin(), extraPlaintext.end(), std::make_pair(offset, byte()));
                if (offset < rangeOffset)
                    range = {before, std::rotate(before, range.begin, range.end)};
                else
                    range = {std::rotate(range.begin, range.end, before), before};
            }

            // swap bytes between the former contiguous plaintext and the beginning of the range
            for (std::size_t i = 0; i < plaintextSize; i++)
            {
                range.begin[i].first = offset + i;
                std::swap(plaintext[i], range.begin[i].second);
            }

            offset = rangeOffset;
        }
    }

    // check that there is enough known plaintext
    if (plaintext.size() < Attack::CONTIGUOUS_SIZE)
        throw Error("not enough contiguous plaintext (" + std::to_string(plaintext.size()) +
                    " bytes available, minimum is " + std::to_string(Attack::CONTIGUOUS_SIZE) + ")");
    if (plaintext.size() + extraPlaintext.size() < Attack::ATTACK_SIZE)
        throw Error("not enough plaintext (" + std::to_string(plaintext.size() + extraPlaintext.size()) +
                    " bytes available, minimum is " + std::to_string(Attack::ATTACK_SIZE) + ")");

    // reorder remaining extra plaintext for filtering
    {
        auto before = std::lower_bound(extraPlaintext.begin(), extraPlaintext.end(), std::make_pair(offset, byte()));
        std::reverse(extraPlaintext.begin(), before);
        std::inplace_merge(extraPlaintext.begin(), before, extraPlaintext.end(),
                           [this](const std::pair<std::size_t, byte>& a, const std::pair<std::size_t, byte>& b) {
                               return absdiff(a.first, offset + Attack::CONTIGUOUS_SIZE) <
                                      absdiff(b.first, offset + Attack::CONTIGUOUS_SIZE);
                           });
    }

    // compute keystream
    std::transform(plaintext.begin(), plaintext.end(), ciphertext.begin() + offset, std::back_inserter(keystream),
                   std::bit_xor<byte>());
}
