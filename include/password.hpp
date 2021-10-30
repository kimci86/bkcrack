#ifndef BKCRACK_PASSWORD_HPP
#define BKCRACK_PASSWORD_HPP

#include "Keys.hpp"
#include <bitset>

/// \file password.hpp

/// Class to recover a password from internal keys
class Recovery
{
    public:
        /// Constructor
        Recovery(const Keys& keys, const bytevec& charset, std::vector<std::string>& solutions,
                 bool exhaustive, std::atomic<bool>& stop);

        /// Look for a password of the given length (at most 6)
        void recoverShortPassword(std::size_t length);

        /// \brief Look for a password of given length starting with a given prefix
        /// \param prefix The beginning of the password we are trying to complete
        /// \param length Length of the password (at least 7 + prefix's length)
        void recoverLongPassword(const std::string& prefix, std::size_t length);

    private:
        void recoverLongPassword(const Keys& initial, std::size_t length);

        // try to recover a password of length 6
        void recover(const Keys& initial);

        // iterate recursively on possible Y values
        void recursion(int i);

        u32arr<7> x, y, z;
        bytearr<6> p;

        std::bitset<1<<8> zm1_24_32;
        std::bitset<1<<16> z0_16_32;
        uint32 x0;

        const bytevec& charset;
        std::vector<std::string>& solutions;
        std::string prefix;
        std::size_t erase = 0;

        const bool exhaustive;
        std::atomic<bool>& stop;
};

/// \brief Try to recover the password associated with the given keys
/// \param keys Internal keys for which a password is wanted
/// \param charset The set of characters with which to constitute candidate passwords
/// \param min_length The smallest password length to try
/// \param max_length The greatest password length to try
/// \param exhaustive True to try and find all valid passwords,
///                   false to stop searching after the first one is found
/// \param progress Pointer to report progress
/// \return A vector of passwords associated with the given keys.
///         A vector is needed instead of a single string because there can be
///         collisions (i.e. several passwords for the same keys).
std::vector<std::string> recoverPassword(const Keys& keys, const bytevec& charset,
    std::size_t min_length, std::size_t max_length, bool exhaustive, std::atomic<Progress>* progress = nullptr);

#endif // BKCRACK_PASSWORD_HPP
