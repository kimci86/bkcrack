#ifndef BKCRACK_KEYSTREAMTAB_HPP
#define BKCRACK_KEYSTREAMTAB_HPP

#include <bitset>

#include "types.hpp"

/// Lookup tables for keystream related computations
class KeystreamTab
{
    public:
        /// \return the keystream byte ki associated to a Zi value
        /// \note Only Zi[2,16) is used
        static inline byte getByte(uint32 zi)
        {
            return instance.keystreamtab[(zi & MASK_0_16) >> 2];
        }

        /// \return a sorted array of 64 Zi[2,16) values such that
        /// getByte(zi) is equal to ki
        static inline const u32arr<64>& getZi_2_16_array(byte ki)
        {
            return instance.keystreaminvtab[ki];
        }

        /// \return a vector of Zi[2,16) values having given [10,16) bits
        /// such that getByte(zi) is equal to ki
        /// \note the vector contains one element on average
        static inline const u32vec& getZi_2_16_vector(byte ki, uint32 zi_10_16)
        {
            return instance.keystreaminvfiltertab[ki][(zi_10_16 & MASK_0_16) >> 10];
        }

        /// \return true if the vector returned by getZi_2_16_vector is not empty,
        /// false otherwise
        static inline bool hasZi_2_16(byte ki, uint32 zi_10_16)
        {
            return instance.keystreaminvexists[ki][(zi_10_16 & MASK_0_16) >> 10];
        }

    private:
        // initialize lookup tables
        KeystreamTab();

        // lookup tables
        bytearr<1<<14> keystreamtab;
        std::array<u32arr<64>, 256> keystreaminvtab;
        std::array<std::array<u32vec, 64>, 256> keystreaminvfiltertab;
        std::array<std::bitset<64>, 256> keystreaminvexists;

        static const KeystreamTab instance;
};

#endif // BKCRACK_KEYSTREAMTAB_HPP
