#ifndef BKCRACK_KEYSTREAMTAB_HPP
#define BKCRACK_KEYSTREAMTAB_HPP

#include "types.hpp"

#include <bitset>

/// Lookup tables for keystream related computations
class KeystreamTab
{
public:
    /// \return the keystream byte ki associated to a Zi value
    /// \note Only Zi[2,16) is used
    static auto getByte(std::uint32_t zi) -> std::uint8_t
    {
        return instance.keystreamtab[(zi & mask<0, 16>) >> 2];
    }

    /// \return a vector of Zi[2,16) values having given [10,16) bits
    /// such that getByte(zi) is equal to ki
    /// \note the vector contains one element on average
    static auto getZi_2_16_vector(std::uint8_t ki, std::uint32_t zi_10_16) -> const std::vector<std::uint32_t>&
    {
        return instance.keystreaminvfiltertab[ki][(zi_10_16 & mask<0, 16>) >> 10];
    }

    /// \return true if the vector returned by getZi_2_16_vector is not empty,
    /// false otherwise
    static auto hasZi_2_16(std::uint8_t ki, std::uint32_t zi_10_16) -> bool
    {
        return instance.keystreaminvexists[ki][(zi_10_16 & mask<0, 16>) >> 10];
    }

private:
    // initialize lookup tables
    KeystreamTab();

    // lookup tables
    std::array<std::uint8_t, 1 << 14>                           keystreamtab;
    std::array<std::array<std::vector<std::uint32_t>, 64>, 256> keystreaminvfiltertab;
    std::array<std::bitset<64>, 256>                            keystreaminvexists;

    static const KeystreamTab instance;
};

#endif // BKCRACK_KEYSTREAMTAB_HPP
