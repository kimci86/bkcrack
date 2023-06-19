#ifndef BKCRACK_PASSWORD_HPP
#define BKCRACK_PASSWORD_HPP

#include <bitset>

#include "Keys.hpp"
#include "Progress.hpp"

/// \file password.hpp

/// Class to recover a password from internal keys
class Recovery
{
    public:
        /// Constructor
        Recovery(const Keys& keys, const bytevec& charset, std::vector<std::string>& solutions, bool exhaustive, Progress& progress);

        /// Look for a password of length 6 or less
        void recoverShortPassword();

        /// Look for a password of given length (at least 7) starting with the given prefix
        void recoverLongPassword(const bytevec& prefix, std::size_t length);

    private:
        // try to recover a password of length 7 or more
        void recoverLong(const Keys& initial, std::size_t length);

        // try to recover a password of length 6
        void recover(const Keys& initial);

        // iterate recursively on possible Y values
        void recursion(int i);

        // set of characters to generate password candidates
        const bytevec& charset;

        // set of possible Z0[16,31) values considering given character set
        std::bitset<1<<16> z0_16_32;

        // set of possible Z{-1}[24,32) values considering given character set
        std::bitset<1<<8> zm1_24_32;

        // cipher state (X,Y,Z)_i for index i in [0, 6] where the last state (X,Y,Z)_6 is
        // the representation of the password to recover
        u32arr<7> x, y, z;
        uint32 x0; // backup of candidate X value for convenience

        bytearr<6> p;     // password last 6 bytes
        bytevec m_prefix; // password first l-6 bytes

        // Number of password bytes to ignore at the beginning of p array.
        // Useful when looking for a password shorter than 6 bytes.
        std::size_t m_erase = 0;

        std::vector<std::string>& solutions; // shared output vector of valid passwords
        const bool exhaustive;
        Progress& progress;
};

/// \brief Try to recover the password associated with the given keys
/// \param keys Internal keys for which a password is wanted
/// \param charset The set of characters with which to constitute password candidates
/// \param minLength The smallest password length to try
/// \param maxLength The greatest password length to try
/// \param exhaustive True to try and find all valid passwords,
///                   false to stop searching after the first one is found
/// \param progress Object to report progress
/// \return A vector of passwords associated with the given keys.
///         A vector is needed instead of a single string because there can be
///         collisions (i.e. several passwords for the same keys).
std::vector<std::string> recoverPassword(const Keys& keys, const bytevec& charset, std::size_t minLength, std::size_t maxLength, bool exhaustive, Progress& progress);

#endif // BKCRACK_PASSWORD_HPP
