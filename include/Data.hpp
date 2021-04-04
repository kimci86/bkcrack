#ifndef BKCRACK_DATA_HPP
#define BKCRACK_DATA_HPP

#include "types.hpp"
#include "Arguments.hpp"

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

    /// \brief Load ciphertext and plaintext. Compute keystream.
    /// \exception FileError if a file cannot be opened
    /// \exception ZipError if a zip entry cannot be opened
    /// \exception Error if data cannot be used to carry out an attack
    void load(const Arguments& args);

    bytevec ciphertext, ///< ciphertext bytes including encryption header
            plaintext, ///< plaintext bytes
            keystream; ///< keystream bytes

    /// plaintext and keystream offset relative to ciphertext with encryption header
    std::size_t offset = 0;

    /// additional bytes of plaintext with their offset relative to ciphertext with encryption header
    std::vector<std::pair<std::size_t, byte>> extraPlaintext;
};

#endif // BKCRACK_DATA_HPP
