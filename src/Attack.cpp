#include "Attack.hpp"
#include "log.hpp"
#include "Crc32Tab.hpp"
#include "KeystreamTab.hpp"
#include "MultTab.hpp"

Attack::Attack(const Data& data, std::size_t index)
 : data(data), last(std::min(static_cast<std::size_t>(Attack::ATTACK_SIZE), data.plaintext.size()) - 1), index(index - last)
{}

bool Attack::carryout(dword z_2_32)
{
    zlist[last] = z_2_32;
    return exploreZlists(last);
}

Keys Attack::getKeys() const
{
    Keys keys(xlist[7], ylist[7], zlist[7]);

    using rit = std::reverse_iterator<bytevec::const_iterator>;

    // get the keys associated with the initial state
    for(rit i = rit(data.ciphertext.begin() + Data::ENCRYPTION_HEADER_SIZE + data.offset + index + 7); i != data.ciphertext.rend(); ++i)
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

            // find Zi[0,2) from CRC32^1
            zlist[i] &= MASK_2_32; // discard 2 least significant bits
            zlist[i] |= (Crc32Tab::crc32inv(zlist[i], 0) ^ zlist[i-1]) >> 8;

            // get Y{i+1}[24,32)
            if(i + 1 < ylist.size())
                ylist[i+1] = Crc32Tab::getYi_24_32(zlist[i+1], zlist[i]);

            if(exploreZlists(i-1))
                return true;
        }

        return false;
    }
    else // the Z-list is complete so iterate over possible Y values
    {
        // guess Y{last}[8,24) and keep prod == (Y{last}[8,32) - 1) * mult^-1
        for(dword y_8_24 = 0, prod = (MultTab::getMultinv(msb(ylist[last])) << 24) - MultTab::MULTINV;
            y_8_24 < 1 << 24;
            y_8_24 += 1 << 8, prod += MultTab::MULTINV << 8)
            // get possible Y{last}[0,8) values
            for(byte y_0_8 : MultTab::getMsbProdFiber3(msb(ylist[last-1]) - msb(prod)))
                // filter Y{last}[0,8) using Y{last-1}[24,32)
                if(prod + MultTab::getMultinv(y_0_8) - (ylist[last-1] & MASK_24_32) <= MAXDIFF_0_24)
                {
                    ylist[last] = y_0_8 | y_8_24 | (ylist[last] & MASK_24_32);
                    if(exploreYlists(last))
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

    dword x = xlist[7];

    // compare available LSB(Xi) bytes obtained from plaintext with those from the X-list
    for(int i = 8; i <= last; i++)
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
    dword y1_26_32 = Crc32Tab::getYi_24_32(zlist[1], zlist[0]) & MASK_26_32;
    if(((ylist[3] - 1) * MultTab::MULTINV - lsb(x) - 1) * MultTab::MULTINV - y1_26_32 > MAXDIFF_0_26)
        return false;

    // TODO further filtering with extra plaintext

    // all tests passed so the keys are found
    return true;
}
