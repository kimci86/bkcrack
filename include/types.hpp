#ifndef BKCRACK_TYPES_HPP
#define BKCRACK_TYPES_HPP

#include <stdexcept>
#include <cstdint>
#include <vector>
#include <array>

/// Base exception type
class BaseError : public std::runtime_error
{
public:
    /// Constructor
    BaseError(const std::string& type, const std::string& description);
};

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

/// \return the absolute difference between two unsigned values
inline std::size_t absdiff(std::size_t x, std::size_t y)
{
    return x < y ? y - x : x - y;
}

// masks

enum : dword
{
    MASK_0_16  = 0x0000ffff,
    MASK_0_24  = 0x00ffffff,
    MASK_0_26  = 0x03ffffff,
    MASK_26_32 = 0xfc000000,
    MASK_24_32 = 0xff000000,
    MASK_10_32 = 0xfffffc00,
    MASK_8_32  = 0xffffff00,
    MASK_2_32  = 0xfffffffc
};

// maximum difference between integers A and B[x,32) where A = B + somebyte.
// So:
//  A - B[x,32) = B[0,x) + somebyte
//  A - B[x,32) <= mask[0,x) + 0xff

enum : dword
{
    MAXDIFF_0_24 = MASK_0_24 + 0xff,
    MAXDIFF_0_26 = MASK_0_26 + 0xff
};

#endif // BKCRACK_TYPES_HPP
