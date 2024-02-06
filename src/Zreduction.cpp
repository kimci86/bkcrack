#include "Zreduction.hpp"

#include "Attack.hpp"
#include "Crc32Tab.hpp"
#include "KeystreamTab.hpp"

#include <algorithm>
#include <bitset>

Zreduction::Zreduction(const bytevec& keystream)
: keystream(keystream)
{
    index = keystream.size() - 1;
    zi_vector.reserve(1 << 22);

    for (uint32 zi_10_32_shifted = 0; zi_10_32_shifted < 1 << 22; zi_10_32_shifted++)
        if (KeystreamTab::hasZi_2_16(keystream[index], zi_10_32_shifted << 10))
            zi_vector.push_back(zi_10_32_shifted << 10);
}

void Zreduction::reduce(Progress& progress)
{
    // variables to keep track of the smallest Zi[2,32) vector
    bool        tracking = false;
    u32vec      bestCopy;
    std::size_t bestIndex = index, bestSize = TRACK_SIZE;

    // variables to wait for a limited number of steps when a small enough vector is found
    bool        waiting = false;
    std::size_t wait    = 0;

    u32vec zim1_10_32_vector;
    zim1_10_32_vector.reserve(1 << 22);
    std::bitset<1 << 22> zim1_10_32_set;

    progress.done  = 0;
    progress.total = keystream.size() - Attack::CONTIGUOUS_SIZE;

    for (std::size_t i = index; i >= Attack::CONTIGUOUS_SIZE; i--)
    {
        zim1_10_32_vector.clear();
        zim1_10_32_set.reset();
        std::size_t number_of_zim1_2_32 = 0;

        // generate the Z{i-1}[10,32) values
        for (uint32 zi_10_32 : zi_vector)
            for (uint32 zi_2_16 : KeystreamTab::getZi_2_16_vector(keystream[i], zi_10_32))
            {
                // get Z{i-1}[10,32) from CRC32^-1
                uint32 zim1_10_32 = Crc32Tab::getZim1_10_32(zi_10_32 | zi_2_16);
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

                if (bestSize <= WAIT_SIZE)
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
        if (bestIndex != Attack::CONTIGUOUS_SIZE - 1)
            std::swap(zi_vector, bestCopy);
        index = bestIndex;
    }
    else
        index = Attack::CONTIGUOUS_SIZE - 1;
}

void Zreduction::generate()
{
    std::size_t number_of_zi_10_32 = zi_vector.size();
    for (std::size_t i = 0; i < number_of_zi_10_32; i++)
    {
        const u32vec& zi_2_16_vector = KeystreamTab::getZi_2_16_vector(keystream[index], zi_vector[i]);
        for (std::size_t j = 1; j < zi_2_16_vector.size(); j++)
            zi_vector.push_back(zi_vector[i] | zi_2_16_vector[j]);
        zi_vector[i] |= zi_2_16_vector[0];
    }
}

const u32vec& Zreduction::getCandidates() const
{
    return zi_vector;
}

std::size_t Zreduction::getIndex() const
{
    return index;
}
