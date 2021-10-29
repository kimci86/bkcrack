#ifndef BKCRACK_ATTACK_HPP
#define BKCRACK_ATTACK_HPP

#include "types.hpp"
#include "Data.hpp"
#include "Keys.hpp"

/// \file Attack.hpp

/// Class to carry out the attack for a given Z[2,32) value
class Attack
{
    public:
        /// \brief Constructor
        /// \param data Data used to carry out the attack
        /// \param index Index of Z[2,32) values passed to carry out the attack
        /// \param solutions Shared output vector for valid keys
        Attack(const Data& data, std::size_t index, std::vector<Keys>& solutions);

        /// Carry out the attack for the given Z[2,32) value
        void carryout(uint32 z7_2_32);

        enum : std::size_t
        {
            /// Number of contiguous known plaintext bytes required by the attack
            CONTIGUOUS_SIZE = 8,

            /// Total number of known plaintext bytes required by the attack
            ATTACK_SIZE = 12
        };

    private:
        // iterate recursively over Z-lists
        void exploreZlists(int i);

        // iterate recursively over Y-lists
        void exploreYlists(int i);

        // check whether the X-list is valid or not
        void testXlist();

        const Data& data;

        const std::size_t index; // starting index of the used plaintext and keystream

        std::vector<Keys>& solutions; // shared output vector of valid keys

        u32arr<CONTIGUOUS_SIZE> zlist;
        u32arr<CONTIGUOUS_SIZE> ylist; // the first two elements are not used
        u32arr<CONTIGUOUS_SIZE> xlist; // the first four elements are not used
};

/// \brief Iterate on Zi[2,32) candidates to try and find complete internal keys
/// \param data Data used to carry out the attack
/// \param zi_2_32_vector Zi[2,32) candidates
/// \param index Index of the Zi[2,32) values relative to keystream
/// \param exhaustive True to try and find all valid keys,
///                   false to stop searching after the first one is found
std::vector<Keys> attack(const Data& data, const u32vec& zi_2_32_vector, std::size_t index, bool exhaustive);

#endif // BKCRACK_ATTACK_HPP
