#include "Attack.hpp"

#include "Crc32Tab.hpp"
#include "KeystreamTab.hpp"
#include "MultTab.hpp"
#include "log.hpp"

#include <algorithm>
#include <atomic>
#include <thread>

Attack::Attack(const Data& data, std::size_t index, std::vector<Keys>& solutions, std::mutex& solutionsMutex,
               bool exhaustive, Progress& progress)
: data(data)
, index(index + 1 - Attack::contiguousSize)
, solutions(solutions)
, solutionsMutex(solutionsMutex)
, exhaustive(exhaustive)
, progress(progress)
{
}

void Attack::carryout(std::uint32_t z7_2_32)
{
    zlist[7] = z7_2_32;
    exploreZlists(7);
}

void Attack::exploreZlists(int i)
{
    if (i != 0) // the Z-list is not complete so generate Z{i-1}[2,32) values
    {
        // get Z{i-1}[10,32) from CRC32^-1
        const std::uint32_t zim1_10_32 = Crc32Tab::getZim1_10_32(zlist[i]);

        // get Z{i-1}[2,16) values from keystream byte k{i-1} and Z{i-1}[10,16)
        for (const std::uint32_t zim1_2_16 : KeystreamTab::getZi_2_16_vector(data.keystream[index + i - 1], zim1_10_32))
        {
            // add Z{i-1}[2,32) to the Z-list
            zlist[i - 1] = zim1_10_32 | zim1_2_16;

            // find Zi[0,2) from CRC32^1
            zlist[i] &= mask<2, 32>; // discard 2 least significant bits
            zlist[i] |= (Crc32Tab::crc32inv(zlist[i], 0) ^ zlist[i - 1]) >> 8;

            // get Y{i+1}[24,32)
            if (i < 7)
                ylist[i + 1] = Crc32Tab::getYi_24_32(zlist[i + 1], zlist[i]);

            exploreZlists(i - 1);
        }
    }
    else // the Z-list is complete so iterate over possible Y values
    {
        // guess Y7[8,24) and keep prod == (Y7[8,32) - 1) * mult^-1
        for (std::uint32_t y7_8_24 = 0, prod = (MultTab::getMultinv(msb(ylist[7])) << 24) - MultTab::multInv;
             y7_8_24 < 1 << 24; y7_8_24 += 1 << 8, prod += MultTab::multInv << 8)
            // get possible Y7[0,8) values
            for (const std::uint8_t y7_0_8 : MultTab::getMsbProdFiber3(msb(ylist[6]) - msb(prod)))
                // filter Y7[0,8) using Y6[24,32)
                if (prod + MultTab::getMultinv(y7_0_8) - (ylist[6] & mask<24, 32>) <= maxdiff<24>)
                {
                    ylist[7] = y7_0_8 | y7_8_24 | (ylist[7] & mask<24, 32>);
                    exploreYlists(7);
                }
    }
}

void Attack::exploreYlists(int i)
{
    if (i != 3) // the Y-list is not complete so generate Y{i-1} values
    {
        const std::uint32_t fy  = (ylist[i] - 1) * MultTab::multInv;
        const std::uint32_t ffy = (fy - 1) * MultTab::multInv;

        // get possible LSB(Xi)
        for (const std::uint8_t xi_0_8 : MultTab::getMsbProdFiber2(msb(ffy - (ylist[i - 2] & mask<24, 32>))))
        {
            // compute corresponding Y{i-1}
            const std::uint32_t yim1 = fy - xi_0_8;

            // filter values with Y{i-2}[24,32)
            if (ffy - MultTab::getMultinv(xi_0_8) - (ylist[i - 2] & mask<24, 32>) <= maxdiff<24> &&
                msb(yim1) == msb(ylist[i - 1]))
            {
                // add Y{i-1} to the Y-list
                ylist[i - 1] = yim1;

                // set Xi value
                xlist[i] = xi_0_8;

                exploreYlists(i - 1);
            }
        }
    }
    else // the Y-list is complete so check if the corresponding X-list is valid
        testXlist();
}

void Attack::testXlist()
{
    // compute X7
    for (int i = 5; i <= 7; i++)
        xlist[i] = (Crc32Tab::crc32(xlist[i - 1], data.plaintext[index + i - 1]) & mask<8, 32>) // discard the LSB
                   | lsb(xlist[i]);                                                             // set the LSB

    // compute X3
    std::uint32_t x = xlist[7];
    for (int i = 6; i >= 3; i--)
        x = Crc32Tab::crc32inv(x, data.plaintext[index + i]);

    // check that X3 fits with Y1[26,32)
    const std::uint32_t y1_26_32 = Crc32Tab::getYi_24_32(zlist[1], zlist[0]) & mask<26, 32>;
    if (((ylist[3] - 1) * MultTab::multInv - lsb(x) - 1) * MultTab::multInv - y1_26_32 > maxdiff<26>)
        return;

    // decipher and filter by comparing with remaining contiguous plaintext forward
    Keys keysForward(xlist[7], ylist[7], zlist[7]);
    keysForward.update(data.plaintext[index + 7]);
    for (auto p = data.plaintext.begin() + index + 8, c = data.ciphertext.begin() + data.offset + index + 8;
         p != data.plaintext.end(); ++p, ++c)
    {
        if ((*c ^ keysForward.getK()) != *p)
            return;
        keysForward.update(*p);
    }

    std::size_t indexForward = data.offset + data.plaintext.size();

    // and also backward
    Keys keysBackward(x, ylist[3], zlist[3]);
    for (auto p = std::reverse_iterator{data.plaintext.begin() + index + 3},
              c = std::reverse_iterator{data.ciphertext.begin() + data.offset + index + 3};
         p != data.plaintext.rend(); ++p, ++c)
    {
        keysBackward.updateBackward(*c);
        if ((*c ^ keysBackward.getK()) != *p)
            return;
    }

    std::size_t indexBackward = data.offset;

    // continue filtering with extra known plaintext
    for (const auto& [extraIndex, extraByte] : data.extraPlaintext)
    {
        std::uint8_t p;
        if (extraIndex < indexBackward)
        {
            keysBackward.updateBackward(data.ciphertext, indexBackward, extraIndex);
            indexBackward = extraIndex;
            p             = data.ciphertext[indexBackward] ^ keysBackward.getK();
        }
        else
        {
            keysForward.update(data.ciphertext, indexForward, extraIndex);
            indexForward = extraIndex;
            p            = data.ciphertext[indexForward] ^ keysForward.getK();
        }

        if (p != extraByte)
            return;
    }

    // all tests passed so the keys are found

    // get the keys associated with the initial state
    keysBackward.updateBackward(data.ciphertext, indexBackward, 0);

    {
        const auto lock = std::scoped_lock{solutionsMutex};
        solutions.push_back(keysBackward);
    }

    progress.log([&keysBackward](std::ostream& os) { os << "Keys: " << keysBackward << std::endl; });

    if (!exhaustive)
        progress.state = Progress::State::EarlyExit;
}

std::vector<Keys> attack(const Data& data, const std::vector<std::uint32_t>& zi_2_32_vector, int& start,
                         std::size_t index, int jobs, const bool exhaustive, Progress& progress)
{
    const std::uint32_t* candidates = zi_2_32_vector.data();
    const auto           size       = static_cast<int>(zi_2_32_vector.size());

    std::vector<Keys> solutions;
    std::mutex        solutionsMutex;
    Attack            worker(data, index, solutions, solutionsMutex, exhaustive, progress);

    progress.done  = start;
    progress.total = size;

    const auto threadCount        = std::clamp(jobs, 1, size);
    auto       threads            = std::vector<std::thread>{};
    auto       nextCandidateIndex = std::atomic<int>{start};
    for (auto i = 0; i < threadCount; ++i)
        threads.emplace_back(
            [&nextCandidateIndex, size, &progress, candidates, worker]() mutable
            {
                for (auto i = nextCandidateIndex++; i < size; i = nextCandidateIndex++)
                {
                    worker.carryout(candidates[i]);
                    progress.done++;

                    if (progress.state != Progress::State::Normal)
                        break;
                }
            });
    for (auto& thread : threads)
        thread.join();

    start = nextCandidateIndex;

    return solutions;
}
