#ifndef BKCRACK_ZIP_HPP
#define BKCRACK_ZIP_HPP

/// \file zip.hpp
/// \brief Parse zip entries metadata and read raw content
///
/// This graph shows how functions and classes from this file work together:
/// \dot
/// digraph {
///     node [ fontsize=10 ];
///     edge [ fontsize=10 ];
///
///     filename [ label="archive and entry names" ];
///     filestream [ label="std::ifstream" ];
///     ZipIterator [ URL="\ref ZipIterator" ];
///     ZipEntry [ URL="\ref ZipEntry" ];
///     entrystream [ label="std::ifstream" ];
///     bytevec [ URL="\ref bytevec" ];
///
///     filename -> filestream [ label="openInput", URL="\ref openInput"];
///     filestream -> ZipIterator [ label="locateZipEntries", URL="\ref locateZipEntries"];
///     ZipIterator -> ZipIterator [ label="operator++", URL="\ref ZipIterator::operator++()"];
///     ZipIterator -> ZipEntry [ label="operator*", URL="\ref ZipIterator::operator*"];
///     ZipEntry -> entrystream [ label="openZipEntry", URL="\ref openZipEntry"];
///     entrystream -> bytevec [ label="loadStream", URL="\ref loadStream"];
///
///     filename -> entrystream [ label="openZipEntry", URL="\ref openZipEntry"];
///     filename -> bytevec [ label="loadZipEntry", URL="\ref loadZipEntry"];
/// }
/// \enddot
///
/// \note Zip64 extensions are supported.
/// \limitation Spanned or split zip files are not supported.
/// \limitation Strong encryption (SES) is not supported.
/// In particular, central directory encryption is not supported.
/// \limitation Language Encoding (EFS) is not supported. (\ref APPNOTE "APPNOTE.TXT", Appendix D)
///
/// \see \ref APPNOTE "APPNOTE.TXT"

#include "file.hpp"
#include "Keys.hpp"

/// Exception thrown when parsing a zip file fails
class ZipError : public BaseError
{
    public:
        /// Constructor
        ZipError(const std::string& description);
};

/// Information about a zip entry
struct ZipEntry
{
    /// Encryption algorithm
    enum class Encryption
    {
        None,        ///< No encryption
        Traditional, ///< Traditional PKWARE encryption (ZipCrypto), vulnerable to known plaintext attack
        Unsupported  ///< Other encryption (DES, RC2, 3DES, AES, Blowfish, Twofish, RC4)
    };

    /// Compression algorithm
    enum class Compression
    {
        Stored,
        Deflate,
        Unknown
    };

    std::string name;        ///< File name
    Encryption encryption;   ///< Encryption method
    Compression compression; ///< Compression method
    uint32 crc32;            ///< CRC-32
    uint64 offset;           ///< Offset of local file header
    uint64 size;             ///< Packed data size
};

/// \brief Single-pass input iterator that reads successive ZipEntry objects from a stream
///
/// Inspired by \c std::istreambuf_iterator.
class ZipIterator : public std::iterator<std::input_iterator_tag, const ZipEntry>
{
    public:
        /// Construct end-of-stream iterator
        ZipIterator() = default;

        /// \brief Construct the iterator from an input stream pointing to the
        /// beginning of a central directory record.
        ///
        /// If the input stream does not point to a central directory record,
        /// then the end-of-stream iterator is constructed.
        ZipIterator(std::istream& is);

        /// \brief Get the current ZipEntry
        /// \pre The iterator must be valid
        const ZipEntry& operator*() const { return m_entry; }

        /// \brief Access a member of the current ZipEntry
        /// \pre The iterator must be valid
        const ZipEntry* operator->() const { return &m_entry; }

        /// \brief Read the next central directory record if any or assign end-of-stream iterator
        /// \pre The iterator must be valid
        ZipIterator& operator++();

        /// \copydoc operator++
        ZipIterator operator++(int);

        /// Test if both iterators are end-of-stream or if both are valid
        bool equal(const ZipIterator& other) const
        {
            return (m_is == nullptr) == (other.m_is == nullptr);
        }

    private:
        std::istream* m_is = nullptr;
        ZipEntry m_entry;
};

/// \brief Test if iterators are equivalent with ZipIterator.equal()
/// \relates ZipIterator
inline bool operator==(const ZipIterator& lhs, const ZipIterator& rhs)
{
    return lhs.equal(rhs);
}

/// \brief Test if iterators are not equivalent with ZipIterator.equal()
/// \relates ZipIterator
inline bool operator!=(const ZipIterator& lhs, const ZipIterator& rhs)
{
    return !lhs.equal(rhs);
}

/// \brief Locate the central directory and return a ZipIterator pointing to the first entry
/// \exception ZipError if the input stream does not contain a valid zip archive
ZipIterator locateZipEntries(std::istream& is);

/// \brief Set the input position indicator at the beginning of \a entry data
/// \exception ZipError if the input stream does not contain \a entry at the expected offset
std::istream& openZipEntry(std::istream& is, const ZipEntry& entry);

/// \brief Open an input file stream, find a zip entry with the given name and
/// set the input position indicator at the beginning the corresponding data.
///
/// \exception FileError if the archive file cannot be opened
/// \exception ZipError if the opened file is not a valid zip archive
/// \exception ZipError if the opened file does not contain an entry with the given name
/// \exception ZipError if the given entry does not use the expected encryption algorithm
/// \exception ZipError if the opened file does not contain the entry at the expected offset
std::ifstream openZipEntry(const std::string& archive, const std::string& entry, ZipEntry::Encryption expected, std::size_t& size);

/// \brief Open an input file stream, find a zip entry with the given name and
/// load at most \a size bytes of the corresponding data.
///
/// \copydetails openZipEntry(const std::string&, const std::string&, ZipEntry::Encryption, std::size_t&)
bytevec loadZipEntry(const std::string& archive, const std::string& entry, ZipEntry::Encryption expected, std::size_t size);

/// \brief Copy a zip file from \a is into \a os changing the encrypted data using the given keys.
/// \exception ZipError if the input stream does not contain a valid zip archive
void changeKeys(std::istream& is, std::ostream& os, const Keys& oldKeys, const Keys& newKeys);

#endif // BKCRACK_ZIP_HPP
