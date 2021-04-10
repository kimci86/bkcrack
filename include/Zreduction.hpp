#ifndef BKCRACK_ZREDUCTION_HPP
#define BKCRACK_ZREDUCTION_HPP

#include "types.hpp"

/// Generate and reduce Z values
class Zreduction
{
    public:
        /// Constructor generating Zi[10,32) values from the last keystream byte
        Zreduction(const bytevec& keystream);

        /// Reduce Zi[10,32) number using extra contiguous keystream
        void reduce();

        /// Extend Zi[10,32) values into Zi[2,32) values using keystream
        void generate();

        /// \return the number of Zi[2,32) values
        std::size_t size() const;

        /// \return a pointer to the beginning of the Zi[2,32) values
        const uint32* data() const;

        /// \return the index of the Zi[2,32) values relative to keystream
        std::size_t getIndex() const;

    private:
        enum : std::size_t
        {
            WAIT_SIZE  = 1 << 8,
            TRACK_SIZE = 1 << 16
        };

        const bytevec& keystream;
        // After constructor or reduce(), contains Z[10,32) values.
        // After generate(), contains Zi[2,32) values.
        u32vec zi_vector;
        std::size_t index;
};

#endif // BKCRACK_ZREDUCTION_HPP
