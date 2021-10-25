#ifndef BKCRACK_DATA_HPP
#define BKCRACK_DATA_HPP

#include <map>

#include "types.hpp"

/// Structure to hold the data needed for an attack
struct Data
{
    enum : std::size_t { ENCRYPTION_HEADER_SIZE = 12 };

    /// Exception thrown if data cannot be used to carry out an attack
    class Error : public BaseError
    {
        public:
            /// Constructor
            Error(const std::string& description);
    };

    /// \brief Construct data and check it can be used to carry out an attack
    /// \param ciphertext Ciphertext bytes including encryption header
    /// \param plaintext Plaintext bytes
    /// \param offset Plaintext offset relative to ciphertext without encryption header (may be negative)
    /// \param extraPlaintext Additional bytes of plaintext with their offset relative to ciphertext without encryption header (may be negative)
    /// \exception Error if the given data cannot be used to carry out an attack
    Data(bytevec ciphertext, bytevec plaintext, int offset, const std::map<int, byte>& extraPlaintext);

    bytevec ciphertext, ///< ciphertext bytes including encryption header
            plaintext, ///< plaintext bytes
            keystream; ///< keystream bytes

    /// plaintext and keystream offset relative to ciphertext with encryption header
    std::size_t offset;

    /// additional bytes of plaintext with their offset relative to ciphertext with encryption header
    std::vector<std::pair<std::size_t, byte>> extraPlaintext;
};

#endif // BKCRACK_DATA_HPP
