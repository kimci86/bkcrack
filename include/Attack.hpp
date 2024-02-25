#ifndef BKCRACK_ATTACK_HPP
#define BKCRACK_ATTACK_HPP

#include "Data.hpp"
#include "Keys.hpp"
#include "Progress.hpp"
#include "types.hpp"

#include <mutex>

/// \file Attack.hpp

/// Class to carry out the attack for a given Z[2,32) value
class Attack
{
public:
    /// \brief Constructor
    /// \param data Data used to carry out the attack
    /// \param index Index of Z[2,32) values passed to carry out the attack
    /// \param solutions Shared output vector for valid keys
    /// \param solutionsMutex Mutex to protect \a solutions from concurrent access
    /// \param exhaustive True to try and find all valid keys,
    ///                   false to stop searching after the first one is found
    /// \param progress Object to report progress
    Attack(const Data& data, std::size_t index, std::vector<Keys>& solutions, std::mutex& solutionsMutex,
           bool exhaustive, Progress& progress);

    /// Carry out the attack for the given Z[2,32) value
    void carryout(std::uint32_t z7_2_32);

    /// Number of contiguous known plaintext bytes required by the attack
    static constexpr std::size_t CONTIGUOUS_SIZE = 8;

    /// Total number of known plaintext bytes required by the attack
    static constexpr std::size_t ATTACK_SIZE = 12;

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
    std::mutex&        solutionsMutex;
    const bool         exhaustive;
    Progress&          progress;

    std::array<std::uint32_t, CONTIGUOUS_SIZE> zlist;
    std::array<std::uint32_t, CONTIGUOUS_SIZE> ylist; // the first two elements are not used
    std::array<std::uint32_t, CONTIGUOUS_SIZE> xlist; // the first four elements are not used
};

/// \brief Iterate on Zi[2,32) candidates to try and find complete internal keys
/// \param data Data used to carry out the attack
/// \param zi_2_32_vector Zi[2,32) candidates
/// \param start Starting index of Zi[2,32) candidates in zi_2_32_vector to try.
///              Also used as an output parameter to tell where to restart.
/// \param index Index of the Zi[2,32) values relative to keystream
/// \param jobs Number of threads to use
/// \param exhaustive True to try and find all valid keys,
///                   false to stop searching after the first one is found
/// \param progress Object to report progress
std::vector<Keys> attack(const Data& data, const std::vector<std::uint32_t>& zi_2_32_vector, int& start,
                         std::size_t index, int jobs, bool exhaustive, Progress& progress);

#endif // BKCRACK_ATTACK_HPP
