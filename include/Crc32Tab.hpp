#ifndef BKCRACK_CRC32TAB_HPP
#define BKCRACK_CRC32TAB_HPP

#include "types.hpp"

/// Lookup tables for CRC32 related computations
class Crc32Tab
{
    public:
        /// \return CRC32 using a lookup table
        static inline uint32 crc32(uint32 pval, byte b)
        {
            return pval >> 8 ^ instance.crctab[lsb(pval) ^ b];
        }

        /// \return CRC32^-1 using a lookup table
        static inline uint32 crc32inv(uint32 crc, byte b)
        {
            return crc << 8 ^ instance.crcinvtab[msb(crc)] ^ b;
        }

        /// \return Yi[24,32) from Zi and Z{i-1} using CRC32^-1
        static inline uint32 getYi_24_32(uint32 zi, uint32 zim1)
        {
            return (crc32inv(zi, 0) ^ zim1) << 24;
        }

        /// \return Z{i-1}[10,32) from Zi[2,32) using CRC32^-1
        static inline uint32 getZim1_10_32(uint32 zi_2_32)
        {
            return crc32inv(zi_2_32, 0) & MASK_10_32; // discard 10 least significant bits
        }

    private:
        // initialize lookup tables
        Crc32Tab();

        // lookup tables
        u32arr<256> crctab;
        u32arr<256> crcinvtab;

        // CRC32 polynomial representation
        enum : uint32 { CRCPOL = 0xedb88320 };

        static const Crc32Tab instance;
};

#endif // BKCRACK_CRC32TAB_HPP
