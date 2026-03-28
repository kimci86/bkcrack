#include "bkcrack/Data.hpp"

#include <bkcrack/Attack.hpp>

#include <algorithm>
#include <functional>
#include <iterator>
#include <ranges>

Data::Error::Error(const std::string& description)
: BaseError{"Data error", description}
{
}

Data::Data(std::vector<std::uint8_t> ciphertextArg, std::vector<std::uint8_t> plaintextArg, int offsetArg,
           const std::map<int, std::uint8_t>& extraPlaintextArg)
: ciphertext{std::move(ciphertextArg)}
, plaintext{std::move(plaintextArg)}
{
    // validate lengths
    if (ciphertext.size() < Attack::attackSize)
        throw Error{"ciphertext is too small for an attack (minimum length is " + std::to_string(Attack::attackSize) +
                    ")"};
    if (ciphertext.size() < plaintext.size())
        throw Error{"ciphertext is smaller than plaintext"};

    // validate offsets
    constexpr auto minimumOffset = -static_cast<int>(encryptionHeaderSize);
    if (offsetArg < minimumOffset)
        throw Error{"plaintext offset " + std::to_string(offsetArg) + " is too small (minimum is " +
                    std::to_string(minimumOffset) + ")"};
    if (ciphertext.size() < encryptionHeaderSize + offsetArg + plaintext.size())
        throw Error{"plaintext offset " + std::to_string(offsetArg) + " is too large"};

    if (!extraPlaintextArg.empty() && extraPlaintextArg.begin()->first < minimumOffset)
        throw Error{"extra plaintext offset " + std::to_string(extraPlaintextArg.begin()->first) +
                    " is too small (minimum is " + std::to_string(minimumOffset) + ")"};
    if (!extraPlaintextArg.empty() && ciphertext.size() <= encryptionHeaderSize + extraPlaintextArg.rbegin()->first)
        throw Error{"extra plaintext offset " + std::to_string(extraPlaintextArg.rbegin()->first) + " is too large"};

    // shift offsets to absolute values
    offset = encryptionHeaderSize + offsetArg;
    for (const auto& [extraOffset, extraByte] : extraPlaintextArg)
        extraPlaintext.emplace_back(encryptionHeaderSize + extraOffset, extraByte);

    // merge contiguous plaintext with adjacent extra plaintext
    {
        // Split extra plaintext into three ranges:
        // - [extraPlaintext.begin(), before) before contiguous plaintext
        // - [before, after)                  overlapping contiguous plaintext
        // - [after, extraPlaintext.end())    after contiguous plaintext

        auto before = std::ranges::lower_bound(extraPlaintext, std::pair{offset, std::uint8_t{}});
        auto after  = std::ranges::lower_bound(extraPlaintext, std::pair{offset + plaintext.size(), std::uint8_t{}});

        // overwrite overlapping plaintext
        for (const auto& [extraOffset, extraByte] : std::ranges::subrange{before, after})
            plaintext[extraOffset - offset] = extraByte;

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
        auto range = std::ranges::subrange{extraPlaintext.begin(), extraPlaintext.begin()}; // empty

        for (auto it = extraPlaintext.begin(); it != extraPlaintext.end();)
        {
            auto current = std::ranges::subrange{it, ++it};
            while (it != extraPlaintext.end() && it->first == current.back().first + 1)
                current = {current.begin(), ++it};

            range = std::ranges::max(range, current, {}, std::size<decltype(range)>);
        }

        if (plaintext.size() < range.size())
        {
            const auto plaintextSize = plaintext.size();
            const auto rangeOffset   = range.front().first;

            // append last bytes from the range to contiguous plaintext
            for (const auto& [extraOffset, extraByte] : range | std::views::drop(plaintextSize))
                plaintext.push_back(extraByte);

            // remove those bytes from the range
            range = {range.begin(), extraPlaintext.erase(range.begin() + plaintextSize, range.end())};
            if (plaintextSize == 0)
                range = {range.end(), range.end()}; // begin iterator was invalidated

            // rotate extra plaintext so that it will be sorted at the end of this scope
            {
                const auto before = std::ranges::lower_bound(extraPlaintext, std::pair{offset, std::uint8_t{}});
                if (offset < rangeOffset)
                    range = {before, std::rotate(before, range.begin(), range.end())};
                else
                    range = {std::rotate(range.begin(), range.end(), before), before};
            }

            // swap bytes between the former contiguous plaintext and the beginning of the range
            for (auto i = std::size_t{}; i < plaintextSize; i++)
            {
                range[i].first = offset + i;
                std::swap(plaintext[i], range[i].second);
            }

            offset = rangeOffset;
        }
    }

    // check that there is enough known plaintext
    if (plaintext.size() < Attack::contiguousSize)
        throw Error{"not enough contiguous plaintext (" + std::to_string(plaintext.size()) +
                    " bytes available, minimum is " + std::to_string(Attack::contiguousSize) + ")"};
    if (plaintext.size() + extraPlaintext.size() < Attack::attackSize)
        throw Error{"not enough plaintext (" + std::to_string(plaintext.size() + extraPlaintext.size()) +
                    " bytes available, minimum is " + std::to_string(Attack::attackSize) + ")"};

    // reorder remaining extra plaintext for filtering
    {
        const auto before = std::ranges::lower_bound(extraPlaintext, std::pair{offset, std::uint8_t{}});
        std::ranges::reverse(std::ranges::subrange{extraPlaintext.begin(), before});
        std::ranges::inplace_merge(
            extraPlaintext, before,
            [this](const std::pair<std::size_t, std::uint8_t>& a, const std::pair<std::size_t, std::uint8_t>& b)
            {
                constexpr auto absdiff = [](std::size_t x, std::size_t y) { return x < y ? y - x : x - y; };
                return absdiff(a.first, offset + Attack::contiguousSize) <
                       absdiff(b.first, offset + Attack::contiguousSize);
            });
    }

    // compute keystream
    std::ranges::transform(plaintext, ciphertext | std::views::drop(offset), std::back_inserter(keystream),
                           std::bit_xor<>());
}
