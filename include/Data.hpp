#ifndef BKCRACK_DATA_HPP
#define BKCRACK_DATA_HPP

#include <stdexcept>

#include "types.hpp"

/// Structure to hold the data
struct Data
{
    enum { headerSize = 12 };

    /// Exception thrown if data can not be used to carry out an attack
    class Error : public std::logic_error
    {
        public:
            /// Constructor
            Error(const std::string& description);
    };

    /// Load ciphertext and plaintext. Compute keystream.
    ///
    /// \exception FileError if a file can not be opened
    /// \exception Error if data can not be used to carry out an attack
    void load(const std::string& cipherfile, const std::string& plainfile);

    bytevec ciphertext, ///< ciphertext bytes including encryption header
            plaintext, ///< plaintext bytes
            keystream; ///< keystream bytes

    /// plaintext and keystream offset relative to ciphertext without encryption header (may be negative)
    int offset = 0;
};

#endif // BKCRACK_DATA_HPP
