#include "Attack.hpp"
#include "log.hpp"
#include "Crc32Tab.hpp"
#include "KeystreamTab.hpp"
#include "MultTab.hpp"

Attack::Attack(const Data& data, std::size_t index)
 : data(data), index(index + 1 - Attack::CONTIGUOUS_SIZE)
{}

bool Attack::carryout(dword z7_2_32)
{
    zlist[7] = z7_2_32;
    return exploreZlists(7);
}

Keys Attack::getKeys() const
{
    Keys keys(xlist[7], ylist[7], zlist[7]);

    // get the keys associated with the initial state
    keys.updateBackward(data.ciphertext, data.offset + index + 7, 0);

    return keys;
}

bool Attack::exploreZlists(int i)
{
    if(i != 0) // the Z-list is not complete so generate Z{i-1}[2,32) values
    {
        // get Z{i-1}[10,32) from CRC32^-1
        dword zim1_10_32 = Crc32Tab::getZim1_10_32(zlist[i]);

        // get Z{i-1}[2,16) values from keystream byte k{i-1} and Z{i-1}[10,16)
        for(dword zim1_2_16 : KeystreamTab::getZi_2_16_vector(data.keystream[index+i-1], zim1_10_32))
        {
            // add Z{i-1}[2,32) to the Z-list
            zlist[i-1] = zim1_10_32 | zim1_2_16;

            // find Zi[0,2) from CRC32^1
            zlist[i] &= MASK_2_32; // discard 2 least significant bits
            zlist[i] |= (Crc32Tab::crc32inv(zlist[i], 0) ^ zlist[i-1]) >> 8;

            // get Y{i+1}[24,32)
            if(i < 7)
                ylist[i+1] = Crc32Tab::getYi_24_32(zlist[i+1], zlist[i]);

            if(exploreZlists(i-1))
                return true;
        }

        return false;
    }
    else // the Z-list is complete so iterate over possible Y values
    {
        // guess Y7[8,24) and keep prod == (Y7[8,32) - 1) * mult^-1
        for(dword y7_8_24 = 0, prod = (MultTab::getMultinv(msb(ylist[7])) << 24) - MultTab::MULTINV;
            y7_8_24 < 1 << 24;
            y7_8_24 += 1 << 8, prod += MultTab::MULTINV << 8)
            // get possible Y7[0,8) values
            for(byte y7_0_8 : MultTab::getMsbProdFiber3(msb(ylist[6]) - msb(prod)))
                // filter Y7[0,8) using Y6[24,32)
                if(prod + MultTab::getMultinv(y7_0_8) - (ylist[6] & MASK_24_32) <= MAXDIFF_0_24)
                {
                    ylist[7] = y7_0_8 | y7_8_24 | (ylist[7] & MASK_24_32);
                    if(exploreYlists(7))
                        return true;
                }

        return false;
    }
}

bool Attack::exploreYlists(int i)
{
    if(i != 3) // the Y-list is not complete so generate Y{i-1} values
    {
        dword fy = (ylist[i] - 1) * MultTab::MULTINV;
        dword ffy = (fy - 1) * MultTab::MULTINV;

        // get possible LSB(Xi)
        for(byte xi_0_8 : MultTab::getMsbProdFiber2(msb(ffy - (ylist[i-2] & MASK_24_32))))
        {
            // compute corresponding Y{i-1}
            dword yim1 = fy - xi_0_8;

            // filter values with Y{i-2}[24,32)
            if(ffy - MultTab::getMultinv(xi_0_8) - (ylist[i-2] & MASK_24_32) <= MAXDIFF_0_24
                && msb(yim1) == msb(ylist[i-1]))
            {
                // add Y{i-1} to the Y-list
                ylist[i-1] = yim1;

                // set Xi value
                xlist[i] = xi_0_8;

                if(exploreYlists(i-1))
                    return true;
            }
        }

        return false;
    }
    else // the Y-list is complete so check if the corresponding X-list is valid
        return testXlist();
}

bool Attack::testXlist()
{
    // compute X7
    for(int i = 5; i <= 7; i++)
        xlist[i] = (Crc32Tab::crc32(xlist[i-1], data.plaintext[index+i-1])
                    & MASK_8_32) // discard the LSB
                    | lsb(xlist[i]); // set the LSB

    // compute X3
    dword x = xlist[7];
    for(int i = 6; i >= 3; i--)
        x = Crc32Tab::crc32inv(x, data.plaintext[index+i]);

    // check that X3 fits with Y1[26,32)
    dword y1_26_32 = Crc32Tab::getYi_24_32(zlist[1], zlist[0]) & MASK_26_32;
    if(((ylist[3] - 1) * MultTab::MULTINV - lsb(x) - 1) * MultTab::MULTINV - y1_26_32 > MAXDIFF_0_26)
        return false;

    // decipher and filter by comparing with remaining contiguous plaintext
    Keys keysForward(xlist[7], ylist[7], zlist[7]);
    keysForward.update(data.plaintext[index+7]);
    for(bytevec::const_iterator p = data.plaintext.begin() + index + 8,
            c = data.ciphertext.begin() + data.offset + index + 8;
            p != data.plaintext.end();
            ++p, ++c)
    {
        if((*c ^ KeystreamTab::getByte(keysForward.getZ())) != *p)
            return false;
        keysForward.update(*p);
    }

    std::size_t indexForward = data.offset + data.plaintext.size();

    // continue filtering with extra known plaintext
    Keys keysBackward(x, ylist[3], zlist[3]);
    std::size_t indexBackward = data.offset + index + 3;

    for(const std::pair<std::size_t, byte>& extra : data.extraPlaintext)
    {
        byte p;
        if(extra.first < indexBackward)
        {
            keysBackward.updateBackward(data.ciphertext, indexBackward, extra.first);
            indexBackward = extra.first;
            p = data.ciphertext[indexBackward] ^ KeystreamTab::getByte(keysBackward.getZ());
        }
        else
        {
            keysForward.update(data.ciphertext, indexForward, extra.first);
            indexForward = extra.first;
            p = data.ciphertext[indexForward] ^ KeystreamTab::getByte(keysForward.getZ());
        }

        if(p != extra.second)
            return false;
    }

    // all tests passed so the keys are found
    return true;
}
