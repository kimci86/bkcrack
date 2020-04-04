#ifndef BKCRACK_ZREDUCTION_HPP
#define BKCRACK_ZREDUCTION_HPP

#include "types.hpp"

/// Generate and reduce Zi[2,32) values
class Zreduction
{
    public:
        /// Constructor
        Zreduction(const bytevec& keystream);

        /// Generate 2^22 Zi[2,32) values from keystream
        void generate();

        /// Reduce Zi[2,32) number using extra information
        void reduce();

        /// \return the number of Zi[2,32) values
        std::size_t size() const;

        /// \return an iterator to the beginning of the Zi[2,32) values
        dwordvec::const_iterator begin() const;

        /// \return an iterator to the end of the Zi[2,32) values
        dwordvec::const_iterator end() const;

        /// \return the index of the Zi[2,32) values relative to keystream
        std::size_t getIndex() const;

    private:
        enum : std::size_t
        {
            WAIT_SIZE  = 1 << 8,
            TRACK_SIZE = 1 << 16
        };

        const bytevec& keystream;
        dwordvec zi_2_32_vector;
        std::size_t index;
};

#endif // BKCRACK_ZREDUCTION_HPP
