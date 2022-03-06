#ifndef BKCRACK_PASSWORD_HPP
#define BKCRACK_PASSWORD_HPP

#include <bitset>

#include "Keys.hpp"
#include "Progress.hpp"

/// Class to recover a password from internal keys
class Recovery
{
    public:
        /// Constructor
        Recovery(const Keys& keys, const bytevec& charset, Progress& progress);

        /// Look for a password of length 6 or less
        bool recoverShortPassword(const Keys& initial);

        /// Look for a password of given length (at least 7)
        bool recoverLongPassword(const Keys& initial, std::size_t length);

        /// \return the password after a successful recovery
        const std::string& getPassword() const;

    private:
        // try to recover a password of length 6
        bool recover(const Keys& initial);

        // iterate recursively on possible Y values
        bool recursion(int i);

        u32arr<7> x, y, z;
        bytearr<6> p;

        std::bitset<1<<8> zm1_24_32;
        std::bitset<1<<16> z0_16_32;
        uint32 x0;

        const bytevec& charset;
        std::string password;

        Progress& progress;
};

/// Try to recover the password associated with the given keys
bool recoverPassword(const std::string& prefix, const Keys& keys, std::size_t max_length, const bytevec& charset, std::string& password, Progress& progress);

#endif // BKCRACK_PASSWORD_HPP
