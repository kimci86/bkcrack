#ifndef BKCRACK_DATA_HPP
#define BKCRACK_DATA_HPP

#include <bkcrack/types.hpp>

#include <map>
#include <optional>

/// Structure to hold the data needed for an attack
struct Data
{
    /// Size of the traditional PKWARE encryption header
    static constexpr std::size_t encryptionHeaderSize = 12;

    /// Exception thrown if data cannot be used to carry out an attack
    class Error : public BaseError
    {
    public:
        /// Constructor
        explicit Error(const std::string& description);
    };

    /// \brief Construct data and check it can be used to carry out an attack
    /// \param ciphertext Ciphertext bytes including encryption header
    /// \param checkByte Plaintext byte at the end of encryption header (offset -1) coming for zip entry metadata.
    ///                  Can be overridden by plaintext or extraPlaintext.
    /// \param plaintext Plaintext bytes
    /// \param offset Plaintext offset relative to ciphertext without encryption header (may be negative)
    /// \param extraPlaintext Additional bytes of plaintext with their offset relative to ciphertext without
    ///                       encryption header (may be negative)
    /// \exception Error if the given data cannot be used to carry out an attack
    Data(std::vector<std::uint8_t> ciphertext, std::optional<std::uint8_t> checkByte,
         std::vector<std::uint8_t> plaintext, int offset, const std::map<int, std::uint8_t>& extraPlaintext);

    std::vector<std::uint8_t> ciphertext; ///< ciphertext bytes including encryption header
    std::vector<std::uint8_t> plaintext;  ///< plaintext bytes
    std::vector<std::uint8_t> keystream;  ///< keystream bytes

    /// plaintext and keystream offset relative to ciphertext with encryption header
    std::size_t offset;

    /// additional bytes of plaintext with their offset relative to ciphertext with encryption header
    std::vector<std::pair<std::size_t, std::uint8_t>> extraPlaintext;
};

#endif // BKCRACK_DATA_HPP
