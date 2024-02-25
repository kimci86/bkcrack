#ifndef BKCRACK_CRC32TAB_HPP
#define BKCRACK_CRC32TAB_HPP

#include "types.hpp"

/// Lookup tables for CRC32 related computations
class Crc32Tab
{
public:
    /// \return CRC32 using a lookup table
    static auto crc32(std::uint32_t pval, std::uint8_t b) -> std::uint32_t
    {
        return pval >> 8 ^ instance.crctab[lsb(pval) ^ b];
    }

    /// \return CRC32^-1 using a lookup table
    static auto crc32inv(std::uint32_t crc, std::uint8_t b) -> std::uint32_t
    {
        return crc << 8 ^ instance.crcinvtab[msb(crc)] ^ b;
    }

    /// \return Yi[24,32) from Zi and Z{i-1} using CRC32^-1
    static auto getYi_24_32(std::uint32_t zi, std::uint32_t zim1) -> std::uint32_t
    {
        return (crc32inv(zi, 0) ^ zim1) << 24;
    }

    /// \return Z{i-1}[10,32) from Zi[2,32) using CRC32^-1
    static auto getZim1_10_32(std::uint32_t zi_2_32) -> std::uint32_t
    {
        return crc32inv(zi_2_32, 0) & mask<10, 32>; // discard 10 least significant bits
    }

private:
    // initialize lookup tables
    Crc32Tab();

    // lookup tables
    std::array<std::uint32_t, 256> crctab;
    std::array<std::uint32_t, 256> crcinvtab;

    static const Crc32Tab instance;
};

#endif // BKCRACK_CRC32TAB_HPP
