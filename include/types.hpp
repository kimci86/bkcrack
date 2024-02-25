#ifndef BKCRACK_TYPES_HPP
#define BKCRACK_TYPES_HPP

/// \file types.hpp
/// \brief Useful types, constants and utility functions

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

/// Base exception type
class BaseError : public std::runtime_error
{
public:
    /// Constructor
    explicit BaseError(const std::string& type, const std::string& description);
};

// utility functions

/// \return the least significant byte of x
constexpr std::uint8_t lsb(std::uint32_t x)
{
    return x;
}

/// \return the most significant byte of x
constexpr std::uint8_t msb(std::uint32_t x)
{
    return x >> 24;
}

/// \return the absolute difference between two unsigned values
inline std::size_t absdiff(std::size_t x, std::size_t y)
{
    return x < y ? y - x : x - y;
}

// constants

/// Constant value for bit masking
template <int begin, int end>
constexpr std::uint32_t mask = ~0u << begin & ~0u >> (32 - end);

/// \brief Maximum difference between 32-bits integers A and B[x,32)
/// knowing that A = B + b and b is a byte.
///
/// The following equations show how the difference is bounded by the given constants:
///
///     A = B + b
///     A = B[0,x) + B[x,32) + b
///     A - B[x,32) = B[0,x) + b
///     A - B[x,32) <= 0xffffffff[0,x) + 0xff
template <int x>
constexpr std::uint32_t maxdiff = mask<0, x> + 0xff;

#endif // BKCRACK_TYPES_HPP
