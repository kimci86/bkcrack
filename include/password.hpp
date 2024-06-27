#ifndef BKCRACK_PASSWORD_HPP
#define BKCRACK_PASSWORD_HPP

#include "Keys.hpp"
#include "Progress.hpp"

/// \file password.hpp

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
