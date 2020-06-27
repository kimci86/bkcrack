#ifndef BKCRACK_ATTACK_HPP
#define BKCRACK_ATTACK_HPP

#include "types.hpp"
#include "Data.hpp"
#include "Keys.hpp"

/// Class to carry out the attack for a given Z[2,32) value
class Attack
{
    public:
        /// Constructor
        ///
        /// \param data Data used to carry out the attack
        /// \param index Index of Z[2,32) values passed to carry out the attack
        Attack(const Data& data, std::size_t index);

        /// Carry out the attack
        bool carryout(dword z7_2_32);

        /// \return the keys after a successful attack
        Keys getKeys() const;

        enum : std::size_t
        {
            /// Number of contiguous known plaintext bytes required by the attack
            CONTIGUOUS_SIZE = 8,

            /// Total number of known plaintext bytes required by the attack
            ATTACK_SIZE = 12
        };

    private:
        // iterate recursively over Z-lists
        bool exploreZlists(int i);

        // iterate recursively over Y-lists
        bool exploreYlists(int i);

        // check whether the X-list is valid or not
        bool testXlist();

        const Data& data;

        const std::size_t index; // starting index of the used plaintext and keystream

        dwordarr<CONTIGUOUS_SIZE> zlist;
        dwordarr<CONTIGUOUS_SIZE> ylist; // the first two elements are not used
        dwordarr<CONTIGUOUS_SIZE> xlist; // the first four elements are not used
};

#endif // BKCRACK_ATTACK_HPP
