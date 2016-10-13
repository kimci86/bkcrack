#ifndef BKCRACK_TYPES_HPP
#define BKCRACK_TYPES_HPP

#include <cstdint>
#include <vector>
#include <array>

// scalar types

using byte = std::uint8_t;
using word = std::uint16_t;
using dword = std::uint32_t;

// container types

template <std::size_t N>
using bytearr = std::array<byte, N>;

template <std::size_t N>
using dwordarr = std::array<dword, N>;

using bytevec = std::vector<byte>;
using dwordvec = std::vector<dword>;

// utility functions

/// \return the least significant byte of x
inline byte lsb(dword x)
{
    return x;
}

/// \return the most significant byte of x
inline byte msb(dword x)
{
    return x >> 24;
}

// masks

enum : dword
{
    mask_0_16  = 0x0000ffff,
    mask_26_32 = 0xfc000000,
    mask_24_32 = 0xff000000,
    mask_10_32 = 0xfffffc00,
    mask_8_32  = 0xffffff00,
    mask_2_32  = 0xfffffffc
};

// maximum difference between integers A and B[x,32) where A = B + somebyte.
// So:
//  A - B[x,32) = B[0,x) + somebyte
//  A - B[x,32) <= mask[0,x) + 0xff

enum : dword
{
    maxdiff_0_24 = 0x00ffffff + 0xff,
    maxdiff_0_26 = 0x03ffffff + 0xff
};

#endif // BKCRACK_TYPES_HPP
