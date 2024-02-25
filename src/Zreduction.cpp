#include "Zreduction.hpp"

#include "Attack.hpp"
#include "Crc32Tab.hpp"
#include "KeystreamTab.hpp"

#include <algorithm>
#include <bitset>

Zreduction::Zreduction(const std::vector<std::uint8_t>& keystream)
: keystream{keystream}
{
    index = keystream.size() - 1;
    zi_vector.reserve(1 << 22);

    for (auto zi_10_32_shifted = std::uint32_t{}; zi_10_32_shifted < 1 << 22; zi_10_32_shifted++)
        if (KeystreamTab::hasZi_2_16(keystream[index], zi_10_32_shifted << 10))
            zi_vector.push_back(zi_10_32_shifted << 10);
}

void Zreduction::reduce(Progress& progress)
{
    // variables to keep track of the smallest Zi[2,32) vector
    constexpr auto trackSizeThreshold = std::size_t{1 << 16};

    auto tracking  = false;
    auto bestCopy  = std::vector<std::uint32_t>{};
    auto bestIndex = index;
    auto bestSize  = trackSizeThreshold;

    // variables to wait for a limited number of steps when a small enough vector is found
    constexpr auto waitSizeThreshold = std::size_t{1 << 8};

    auto waiting = false;
    auto wait    = std::size_t{};

    auto zim1_10_32_vector = std::vector<std::uint32_t>{};
    zim1_10_32_vector.reserve(1 << 22);
    auto zim1_10_32_set = std::bitset<1 << 22>{};

    progress.done  = 0;
    progress.total = keystream.size() - Attack::contiguousSize;

    for (auto i = index; i >= Attack::contiguousSize; i--)
    {
        zim1_10_32_vector.clear();
        zim1_10_32_set.reset();
        auto number_of_zim1_2_32 = std::size_t{};

        // generate the Z{i-1}[10,32) values
        for (const auto zi_10_32 : zi_vector)
            for (const auto zi_2_16 : KeystreamTab::getZi_2_16_vector(keystream[i], zi_10_32))
            {
                // get Z{i-1}[10,32) from CRC32^-1
                const auto zim1_10_32 = Crc32Tab::getZim1_10_32(zi_10_32 | zi_2_16);
                // collect without duplicates only those that are compatible with keystream{i-1}
                if (!zim1_10_32_set[zim1_10_32 >> 10] && KeystreamTab::hasZi_2_16(keystream[i - 1], zim1_10_32))
                {
                    zim1_10_32_vector.push_back(zim1_10_32);
                    zim1_10_32_set.set(zim1_10_32 >> 10);
                    number_of_zim1_2_32 += KeystreamTab::getZi_2_16_vector(keystream[i - 1], zim1_10_32).size();
                }
            }

        // update smallest vector tracking
        if (number_of_zim1_2_32 <= bestSize) // new smallest number of Z[2,32) values
        {
            tracking  = true;
            bestIndex = i - 1;
            bestSize  = number_of_zim1_2_32;
            waiting   = false;
        }
        else if (tracking) // number of Z{i-1}[2,32) values is bigger than bestSize
        {
            if (bestIndex == i) // hit a minimum
            {
                // keep a copy of the vector because size is about to grow
                std::swap(bestCopy, zi_vector);

                if (bestSize <= waitSizeThreshold)
                {
                    // enable waiting
                    waiting = true;
                    wait    = bestSize * 4; // arbitrary multiplicative constant
                }
            }

            if (waiting && --wait == 0)
                break;
        }

        // put result in zi_vector
        std::swap(zi_vector, zim1_10_32_vector);

        progress.done++;
    }

    if (tracking)
    {
        // put bestCopy in zi_vector only if bestIndex is not the index of zi_vector
        if (bestIndex != Attack::contiguousSize - 1)
            std::swap(zi_vector, bestCopy);
        index = bestIndex;
    }
    else
        index = Attack::contiguousSize - 1;
}

void Zreduction::generate()
{
    const auto number_of_zi_10_32 = zi_vector.size();
    for (auto i = std::size_t{}; i < number_of_zi_10_32; i++)
    {
        const auto& zi_2_16_vector = KeystreamTab::getZi_2_16_vector(keystream[index], zi_vector[i]);
        for (auto j = std::size_t{1}; j < zi_2_16_vector.size(); j++)
            zi_vector.push_back(zi_vector[i] | zi_2_16_vector[j]);
        zi_vector[i] |= zi_2_16_vector[0];
    }
}

auto Zreduction::getCandidates() const -> const std::vector<std::uint32_t>&
{
    return zi_vector;
}

auto Zreduction::getIndex() const -> std::size_t
{
    return index;
}
