#include "Attack.hpp"
#include "log.hpp"
#include "Crc32Tab.hpp"
#include "KeystreamTab.hpp"
#include "MultTab.hpp"

Attack::Attack(const Data& data, std::size_t index)
 : data(data), index(index)
{}

bool Attack::carryout(dword z11_2_32)
{
    zlist[11] = z11_2_32;
    return exploreZlists(11);
}

Keys Attack::getKeys() const
{
    Keys keys(xlist[7], ylist[7], zlist[7]);

    using rit = std::reverse_iterator<bytevec::const_iterator>;

    // get the keys associated with the initial state
    for(rit i = rit(data.ciphertext.begin() + data.headerSize + data.offset + index + 7); i != data.ciphertext.rend(); ++i)
        keys.updateBackward(*i);

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

            // find Zi[0,2) from Crc32^1
            zlist[i] &= mask_2_32; // discard 2 least significant bits
            zlist[i] |= (Crc32Tab::crc32inv(zlist[i], 0) ^ zlist[i-1]) >> 8;

            // get Y{i+1}[24,32)
            if(i < 11)
                ylist[i+1] = Crc32Tab::getYi_24_32(zlist[i+1], zlist[i]);

            if(exploreZlists(i-1))
                return true;
        }

        return false;
    }
    else // the Z-list is complete so iterate over possible Y values
    {
        // guess Y11[8,24) and keep prod == (Y11[8,32) - 1) * mult^-1
        for(dword y11_8_24 = 0, prod = (MultTab::getMultinv(msb(ylist[11])) << 24) - MultTab::multinv;
            y11_8_24 < 1 << 24;
            y11_8_24 += 1 << 8, prod += MultTab::multinv << 8)
            // get possible Y11[0,8) values
            for(byte y11_0_8 : MultTab::getMsbProdFiber3(msb(ylist[10]) - msb(prod)))
                // filter Y11[0,8) using Y10[24,32)
                if(prod + MultTab::getMultinv(y11_0_8) - (ylist[10] & mask_24_32) <= maxdiff_0_24)
                {
                    ylist[11] = y11_0_8 | y11_8_24 | (ylist[11] & mask_24_32);
                    if(exploreYlists(11))
                        return true;
                }

        return false;
    }
}

bool Attack::exploreYlists(int i)
{
    if(i != 3) // the Y-list is not complete so generate Y{i-1} values
    {
        dword fy = (ylist[i] - 1) * MultTab::multinv;
        dword ffy = (fy - 1) * MultTab::multinv;

        // get possible LSB(Xi)
        for(byte xi_0_8 : MultTab::getMsbProdFiber2(msb(ffy - (ylist[i-2] & mask_24_32))))
        {
            // compute corresponding Y{i-1}
            dword yim1 = fy - xi_0_8;

            // filter values with Y{i-2}[24,32)
            if(ffy - MultTab::getMultinv(xi_0_8) - (ylist[i-2] & mask_24_32) <= maxdiff_0_24
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
                    & mask_8_32) // discard the LSB
                    | lsb(xlist[i]); // set the LSB

    dword x = xlist[7];

    // compare 4 LSB(Xi) obtained from plaintext with those from the X-list
    for(int i = 8; i <= 11; i++)
    {
        x = Crc32Tab::crc32(x, data.plaintext[index+i-1]);
        if(lsb(x) != lsb(xlist[i]))
            return false;
    }

    // compute X3
    x = xlist[7];
    for(int i = 6; i >= 3; i--)
        x = Crc32Tab::crc32inv(x, data.plaintext[index+i]);

    // check that X3 fits with Y1[26,32)
    dword y1_26_32 = Crc32Tab::getYi_24_32(zlist[1], zlist[0]) & mask_26_32;
    if(((ylist[3] - 1) * MultTab::multinv - lsb(x) - 1) * MultTab::multinv - y1_26_32 > maxdiff_0_26)
        return false;

    // all tests passed so the keys are found
    return true;
}
