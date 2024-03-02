#include "Crc32Tab.hpp"

const Crc32Tab Crc32Tab::instance;

Crc32Tab::Crc32Tab()
{
    // CRC32 polynomial representation
    constexpr auto crcPolynom = 0xedb88320;

    for (auto b = 0; b < 256; b++)
    {
        auto crc = static_cast<std::uint32_t>(b);
        // compute CRC32 from the original definition
        for (auto i = 0; i < 8; i++)
            if (crc & 1)
                crc = crc >> 1 ^ crcPolynom;
            else
                crc = crc >> 1;

        // fill lookup tables
        crctab[b]           = crc;
        crcinvtab[msb(crc)] = crc << 8 ^ b;
    }
}
