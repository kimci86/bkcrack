#ifndef BKCRACK_ZIP_HPP
#define BKCRACK_ZIP_HPP

#include "Keys.hpp"
#include "Progress.hpp"

#include <fstream>
#include <optional>

/// \brief Open a zip archive, parse zip entries metadata and read raw content
///
/// \note Zip64 extensions are supported.
///
/// \limitation Spanned or split zip files are not supported.
/// \limitation Strong encryption (SES) is not supported.
///             In particular, central directory encryption is not supported.
/// \limitation Language Encoding (EFS) is not supported. (\ref APPNOTE "APPNOTE.TXT", Appendix D)
///
/// \see \ref APPNOTE "APPNOTE.TXT"
class Zip
{
public:
    /// Exception thrown when parsing a zip file fails
    class Error : public BaseError
    {
    public:
        /// Constructor
        Error(const std::string& description);
    };

    /// Encryption algorithm
    enum class Encryption
    {
        None,        ///< No encryption
        Traditional, ///< Traditional PKWARE encryption (ZipCrypto), vulnerable to known plaintext attack
        Unsupported  ///< Other encryption (DES, RC2, 3DES, AES, Blowfish, Twofish, RC4)
    };

    /// Compression algorithm. \note This enumeration is not exhaustive.
    enum class Compression
    {
        Store     = 0,
        Shrink    = 1,
        Implode   = 6,
        Deflate   = 8,
        Deflate64 = 9,
        BZip2     = 12,
        LZMA      = 14,
        Zstandard = 93,
        MP3       = 94,
        XZ        = 95,
        JPEG      = 96,
        WavPack   = 97,
        PPMd      = 98,
    };

    /// Information about a zip entry
    struct Entry
    {
        std::string name;             ///< File name
        Encryption  encryption;       ///< Encryption method
        Compression compression;      ///< Compression method. \note It may take a value not listed in Compression
        uint32      crc32;            ///< CRC-32 checksum
        uint64      offset;           ///< Offset of local file header
        uint64      packedSize;       ///< Packed data size
        uint64      uncompressedSize; ///< Uncompressed data size
        byte        checkByte;        ///< Last byte of the encryption header after decryption
    };

    /// Single-pass input iterator that reads successive Entry objects
    class Iterator
    {
    public:
        /// @{
        /// \brief Required types for iterators
        using difference_type   = std::ptrdiff_t;
        using value_type        = const Entry;
        using pointer           = const Entry*;
        using reference         = const Entry&;
        using iterator_category = std::input_iterator_tag;
        /// @}

        /// Construct end-of-stream iterator
        constexpr Iterator() noexcept = default;

        /// Construct an iterator pointing to the beginning of the given archive's central directory,
        /// or end-of-stream iterator if the central directory is not found at the expected offset.
        explicit Iterator(const Zip& archive);

        /// \brief Get the current entry
        /// \pre The iterator must be valid
        const Entry& operator*() const
        {
            return *m_entry;
        }

        /// \brief Access a member of the current entry
        /// \pre The iterator must be valid
        const Entry* operator->() const
        {
            return &(*m_entry);
        }

        /// \brief Read the next central directory record if any or assign end-of-stream iterator
        /// \pre The iterator must be valid
        Iterator& operator++();

        /// \copydoc operator++
        Iterator operator++(int);

        /// Test if iterators are equivalent, i.e. both are end-of-stream or both are valid
        bool operator==(const Zip::Iterator& other) const
        {
            return (m_is == nullptr) == (other.m_is == nullptr);
        }

        /// Test if iterators are not equivalent
        bool operator!=(const Zip::Iterator& other) const
        {
            return !(*this == other);
        }

    private:
        std::istream*        m_is = nullptr;
        std::optional<Entry> m_entry; // optional type allows the end-of-stream iterator to be empty
    };

    /// \brief Open a zip archive from an already opened input stream
    /// \exception Error if the given input stream is not a valid zip archive
    explicit Zip(std::istream& stream);

    /// \brief Open a zip archive from a file
    /// \exception FileError if the file cannot be opened
    /// \exception Error if the opened file is not a valid zip archive
    explicit Zip(const std::string& filename);

    /// Get an iterator pointing to the first entry
    Iterator begin() const
    {
        return Iterator{*this};
    }

    /// Get an end-of-stream iterator
    Iterator end() const
    {
        return Iterator{};
    }

    /// \brief Get the first entry having the given name
    /// \exception Error if the archive does not contain an entry with the given name
    Entry operator[](const std::string& name) const;

    /// \brief Get the entry at the given index
    /// \exception Error if the index is out of bounds
    Entry operator[](std::size_t index) const;

    /// \brief Check that the given entry uses the expected encryption algorithm
    /// \exception Error if the given entry does not use the expected encryption algorithm
    static void checkEncryption(const Entry& entry, Encryption expected);

    /// \brief Set the underlying stream's input position indicator at the beginning the given entry's raw data
    /// \exception Error if the given entry's data is not at the expected offset
    std::istream& seek(const Entry& entry) const;

    /// \brief Load at most \a count bytes of the given entry's raw data
    /// \exception Error if the given entry's data is not at the expected offset
    bytevec load(const Entry& entry, std::size_t count = std::numeric_limits<std::size_t>::max()) const;

    /// \brief Copy the zip file into \a os changing the encrypted data using the given keys
    /// \exception Error if the archive is not a valid zip archive
    void changeKeys(std::ostream& os, const Keys& oldKeys, const Keys& newKeys, Progress& progress) const;

private:
    std::optional<std::ifstream> m_file; // optionally own the stream
    std::istream&                m_is;
    const uint64                 m_centralDirectoryOffset;
};

#endif // BKCRACK_ZIP_HPP
