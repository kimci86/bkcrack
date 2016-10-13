#ifndef BKCRACK_ATTACK_HPP
#define BKCRACK_ATTACK_HPP

#include "types.hpp"
#include "Data.hpp"
#include "Keys.hpp"

/// Class to carry out the attack for a given Z11[2,32) value
class Attack
{
    public:
        /// Constructor
        ///
        /// \param data Data used to carry out the attack
        /// \param index Starting index of the used plaintext and keystream
        Attack(const Data& data, std::size_t index);

        /// Carry out the attack
        bool carryout(dword z11_2_32);

        /// \return the keys after a successful attack
        Keys getKeys() const;

        enum
        {
            /// Number of known plaintext bytes required by the attack
            size = 12
        };

    private:
        // iterate recursively over Z-lists
        bool exploreZlists(int i);

        // iterate recursively over Y-lists
        bool exploreYlists(int i);

        // check whether the X-list is valid or not
        bool testXlist();

        const Data& data;

        const std::size_t index;

        dwordarr<size> zlist;
        dwordarr<size> ylist; // the first two elements are not used
        dwordarr<size> xlist; // the first four elements are not used
};

#endif // BKCRACK_ATTACK_HPP

