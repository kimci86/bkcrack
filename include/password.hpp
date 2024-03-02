#ifndef BKCRACK_PASSWORD_HPP
#define BKCRACK_PASSWORD_HPP

#include "Keys.hpp"
#include "Progress.hpp"

#include <bitset>
#include <mutex>

/// \file password.hpp

/// Class to recover a password from internal keys
class Recovery
{
public:
    /// Constructor
    Recovery(const Keys& keys, const std::vector<std::uint8_t>& charset, std::vector<std::string>& solutions,
             std::mutex& solutionsMutex, bool exhaustive, Progress& progress);

    /// \brief Look for a password of length 6 or less
    ///
    /// Try to derive 6 characters such that updating the given cipher state
    /// with them gives the target cipher state (the password representation).
    /// On success, the current prefix followed by those 6 characters is added
    /// to the shared output vector.
    ///
    /// If the target length is less than 6, the first characters are ignored so that
    /// the saved solution has the target length. This is useful to recover passwords
    /// shorter than 6 characters.
    ///
    /// \pre prefix.size() + 6 == length && initial == Keys{prefix} || length < 6
    void recoverShortPassword(const Keys& initial);

    /// \brief Look for password of length 7 or more
    ///
    /// Recursively iterate on possible prefixes of length-6 characters.
    /// For each prefix, try to recover the last 6 characters like recoverShortPassword.
    ///
    /// \pre prefix.size() + 6 < length && initial == Keys{prefix}
    void recoverLongPassword(const Keys& initial);

    /// Length of the password to recover
    std::size_t length;

    /// The first characters of the password candidate, up to length-6 characters long
    std::string prefix;

    /// Set of characters to generate password candidates
    const std::vector<std::uint8_t>& charset;

private:
    // iterate recursively on possible Y values
    void recursion(int i);

    // set of possible Z0[16,31) values considering given character set
    std::bitset<1 << 16> z0_16_32;

    // set of possible Z{-1}[24,32) values considering given character set
    std::bitset<1 << 8> zm1_24_32;

    // cipher state (X,Y,Z)_i for index i in [0, 6] where the last state (X,Y,Z)_6 is
    // the representation of the password to recover
    std::array<std::uint32_t, 7> x, y, z;
    std::uint32_t                candidateX0; // backup of candidate X value for convenience

    std::array<std::uint8_t, 6> p; // password last 6 bytes

    std::vector<std::string>& solutions; // shared output vector of valid passwords
    std::mutex&               solutionsMutex;
    const bool                exhaustive;
    Progress&                 progress;
};

/// \brief Try to recover the password associated with the given keys
/// \param keys Internal keys for which a password is wanted
/// \param charset The set of characters with which to constitute password candidates
/// \param minLength The smallest password length to try
/// \param maxLength The greatest password length to try
/// \param start Starting point in the password search space.
///              Also used as an output parameter to tell where to restart.
/// \param jobs Number of threads to use
/// \param exhaustive True to try and find all valid passwords,
///                   false to stop searching after the first one is found
/// \param progress Object to report progress
/// \return A vector of passwords associated with the given keys.
///         A vector is needed instead of a single string because there can be
///         collisions (i.e. several passwords for the same keys).
auto recoverPassword(const Keys& keys, const std::vector<std::uint8_t>& charset, std::size_t minLength,
                     std::size_t maxLength, std::string& start, int jobs, bool exhaustive, Progress& progress)
    -> std::vector<std::string>;

#endif // BKCRACK_PASSWORD_HPP
