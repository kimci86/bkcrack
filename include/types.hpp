#ifndef BKCRACK_TYPES_HPP
#define BKCRACK_TYPES_HPP

/// \file types.hpp
/// \brief Typedefs, useful constants and utility functions

#include <stdexcept>
#include <cstdint>
#include <vector>
#include <array>
#include <string>

/// Base exception type
class BaseError : public std::runtime_error
{
public:
    /// Constructor
    BaseError(const std::string& type, const std::string& description);
};

// scalar types

using byte = std::uint8_t;    ///< Unsigned integer type with width of exactly 8 bits
using uint16 = std::uint16_t; ///< Unsigned integer type with width of exactly 16 bits
using uint32 = std::uint32_t; ///< Unsigned integer type with width of exactly 32 bits
using uint64 = std::uint64_t; ///< Unsigned integer type with width of exactly 64 bits

// container types

template <std::size_t N>
using bytearr = std::array<byte, N>; ///< Array of bytes

template <std::size_t N>
using u32arr = std::array<uint32, N>; ///< Array of 32-bits integers

using bytevec = std::vector<byte>;  ///< Vector of bytes
using u32vec = std::vector<uint32>; ///< Vector of 32-bits integers

// utility functions

/// \return the least significant byte of x
inline byte lsb(uint32 x)
{
    return x;
}

/// \return the most significant byte of x
inline byte msb(uint32 x)
{
    return x >> 24;
}

/// \return the absolute difference between two unsigned values
inline std::size_t absdiff(std::size_t x, std::size_t y)
{
    return x < y ? y - x : x - y;
}

// constants

/// Useful constants for masking
enum : uint32
{
    MASK_0_16  = 0x0000ffff,
    MASK_0_24  = 0x00ffffff,
    MASK_0_26  = 0x03ffffff,
    MASK_0_32  = 0xffffffff,
    MASK_26_32 = 0xfc000000,
    MASK_24_32 = 0xff000000,
    MASK_10_32 = 0xfffffc00,
    MASK_8_32  = 0xffffff00,
    MASK_2_32  = 0xfffffffc
};

/// \brief Maximum difference between 32-bits integers A and B[x,32)
/// knowing that A = B + b and b is a byte.
///
/// The following equations show how the difference is bounded by the given constants:
///
///     A = B + b
///     A = B[0,x) + B[x,32) + b
///     A - B[x,32) = B[0,x) + b
///     A - B[x,32) <= 0xffffffff[0,x) + 0xff
enum : uint32
{
    MAXDIFF_0_24 = MASK_0_24 + 0xff,
    MAXDIFF_0_26 = MASK_0_26 + 0xff
};

#endif // BKCRACK_TYPES_HPP
