#ifndef BKCRACK_ZREDUCTION_HPP
#define BKCRACK_ZREDUCTION_HPP

#include "Progress.hpp"
#include "types.hpp"

/// Generate and reduce Z values
class Zreduction
{
public:
    /// Constructor generating Zi[10,32) values from the last keystream byte
    explicit Zreduction(const std::vector<std::uint8_t>& keystream);

    /// Reduce Zi[10,32) number using extra contiguous keystream
    void reduce(Progress& progress);

    /// Extend Zi[10,32) values into Zi[2,32) values using keystream
    void generate();

    /// \return the generated Zi[2,32) values
    const std::vector<std::uint32_t>& getCandidates() const;

    /// \return the index of the Zi[2,32) values relative to keystream
    std::size_t getIndex() const;

private:
    const std::vector<std::uint8_t>& keystream;
    // After constructor or reduce(), contains Z[10,32) values.
    // After generate(), contains Zi[2,32) values.
    std::vector<std::uint32_t> zi_vector;
    std::size_t                index;
};

#endif // BKCRACK_ZREDUCTION_HPP
