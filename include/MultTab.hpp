#ifndef BKCRACK_MULTTAB_HPP
#define BKCRACK_MULTTAB_HPP

#include "types.hpp"

/// Lookup tables for multiplication related computations
class MultTab
{
public:
    /// \return mult * x using a lookup table
    static inline std::uint32_t getMult(std::uint8_t x)
    {
        return instance.multtab[x];
    }

    /// \return mult^-1 * x using a lookup table
    static inline std::uint32_t getMultinv(std::uint8_t x)
    {
        return instance.multinvtab[x];
    }

    /// \return a vector of bytes x such that
    /// msb(x*mult^-1) is equal to msbprod or msbprod-1
    static inline const std::vector<std::uint8_t>& getMsbProdFiber2(std::uint8_t msbprodinv)
    {
        return instance.msbprodfiber2[msbprodinv];
    }

    /// \return a vector of bytes x such that
    /// msb(x*mult^-1) is equal to msbprod, msbprod-1 or msbprod+1
    static inline const std::vector<std::uint8_t>& getMsbProdFiber3(std::uint8_t msbprodinv)
    {
        return instance.msbprodfiber3[msbprodinv];
    }

    /// Multiplicative constant used in traditional PKWARE encryption
    static constexpr std::uint32_t mult = 0x08088405;

    /// Multiplicative inverse of mult modulo 2^32
    static constexpr std::uint32_t multInv = 0xd94fa8cd;
    static_assert(mult * multInv == 1);

private:
    // initialize lookup tables
    MultTab();

    // lookup tables
    std::array<std::uint32_t, 256>             multtab;
    std::array<std::uint32_t, 256>             multinvtab;
    std::array<std::vector<std::uint8_t>, 256> msbprodfiber2;
    std::array<std::vector<std::uint8_t>, 256> msbprodfiber3;

    static const MultTab instance;
};

#endif // BKCRACK_MULTTAB_HPP
