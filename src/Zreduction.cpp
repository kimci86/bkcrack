#include "Zreduction.hpp"
#include "log.hpp"
#include "Attack.hpp"
#include "Crc32Tab.hpp"
#include "KeystreamTab.hpp"
#include <algorithm>
#include <pdqsort/pdqsort.h>

Zreduction::Zreduction(const bytevec& keystream)
 : keystream(keystream)
{}

void Zreduction::generate()
{
    index = keystream.size() - 1;

    zi_2_32_vector.clear();
    zi_2_32_vector.reserve(1<<22);

    for(dword zi_2_16 : KeystreamTab::getZi_2_16_array(keystream.back())) // get 64 Zi[2,16) values
        for(int high = 0; high < 1 << 16; high++) // guess Zi[16,32)
            zi_2_32_vector.push_back(high << 16 | zi_2_16);
}

void Zreduction::reduce()
{
    // variables to keep track of the smallest Zi[2,32) vector
    bool tracking = false;
    dwordvec bestCopy;
    std::size_t bestIndex = index, bestSize = TRACK_SIZE;

    // variables to wait for a limited number of steps when a small enough vector is found
    bool waiting = false;
    std::size_t wait = 0;

    dwordvec zim1_10_32_vector;
    dwordvec zim1_2_32_vector;

    for(std::size_t i = index; i >= Attack::CONTIGUOUS_SIZE; i--)
    {
        zim1_10_32_vector.clear();
        zim1_2_32_vector.clear();

        // generate the Z{i-1}[10,32) values
        for(dword zi_2_32 : zi_2_32_vector)
        {
            // get Z{i-1}[10,32) from CRC32^-1
            dword zim1_10_32 = Crc32Tab::getZim1_10_32(zi_2_32);
            // collect only those that are compatible with keystream{i-1}
            if(KeystreamTab::hasZi_2_16(keystream[i-1], zim1_10_32))
                zim1_10_32_vector.push_back(zim1_10_32);
        }

        // remove duplicates
        pdqsort(zim1_10_32_vector.begin(), zim1_10_32_vector.end());
        zim1_10_32_vector.erase(
            std::unique(zim1_10_32_vector.begin(), zim1_10_32_vector.end()),
            zim1_10_32_vector.end());

        // complete Z{i-1}[10,32) values up to Z{i-1}[2,32)
        for(dword zim1_10_32 : zim1_10_32_vector)
            // get Z{i-1}[2,16) values from keystream byte k{i-1} and Z{i-1}[10,16)
            for(dword zim1_2_16 : KeystreamTab::getZi_2_16_vector(keystream[i-1], zim1_10_32))
                zim1_2_32_vector.push_back(zim1_10_32 | zim1_2_16);

        // update smallest vector tracking
        if(zim1_2_32_vector.size() <= bestSize) // new smallest vector
        {
            tracking = true;
            bestIndex = i-1;
            bestSize = zim1_2_32_vector.size();
            waiting = false;
        }
        else if(tracking) // vector is bigger than bestSize
        {
            if(bestIndex == i) // hit a minimum
            {
                // keep a copy of the vector because size is about to grow
                std::swap(bestCopy, zi_2_32_vector);

                if(bestSize <= WAIT_SIZE)
                {
                    // enable waiting
                    waiting = true;
                    wait = bestSize * 4; // arbitrary multiplicative constant
                }
            }

            if(waiting && --wait == 0)
                break;
        }

        // put result in z_2_32_vector
        std::swap(zi_2_32_vector, zim1_2_32_vector);

        std::cout << progress(keystream.size() - i, keystream.size() - Attack::CONTIGUOUS_SIZE) << std::flush << "\r";
    }

    std::cout << std::endl;

    if(tracking)
    {
        // put bestCopy in z_2_32_vector only if bestIndex is not the index of z_2_32_vector
        if(bestIndex != Attack::CONTIGUOUS_SIZE - 1)
            std::swap(zi_2_32_vector, bestCopy);
        index = bestIndex;
    }
    else
        index = Attack::CONTIGUOUS_SIZE - 1;
}

std::size_t Zreduction::size() const
{
    return zi_2_32_vector.size();
}

dwordvec::const_iterator Zreduction::begin() const
{
    return zi_2_32_vector.begin();
}

dwordvec::const_iterator Zreduction::end() const
{
    return zi_2_32_vector.end();
}

std::size_t Zreduction::getIndex() const
{
    return index;
}
