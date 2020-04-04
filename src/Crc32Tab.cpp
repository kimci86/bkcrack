#include "Crc32Tab.hpp"

const Crc32Tab Crc32Tab::instance;

Crc32Tab::Crc32Tab()
{
    for(int b = 0; b < 256; b++)
    {
        dword crc = b;
        // compute CRC32 from the original definition
        for(int i = 0; i < 8; i++)
            if(crc & 1)
                crc = crc >> 1 ^ CRCPOL;
            else
                crc = crc >> 1;

        // fill lookup tables
        crctab[b] = crc;
        crcinvtab[msb(crc)] = crc << 8 ^ b;
    }
}
