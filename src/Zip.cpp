#include "Zip.hpp"

#include "file.hpp"

#include <algorithm>
#include <iterator>
#include <map>

namespace
{

template <typename T, std::size_t N = sizeof(T)>
std::istream& read(std::istream& is, T& x)
{
    static_assert(N <= sizeof(T), "read requires output type to have at least N bytes");

    // We make no assumption about platform endianness.
    x = T();
    for (std::size_t index = 0; index < N; index++)
        x |= static_cast<T>(is.get()) << (8 * index);

    return is;
}

std::istream& read(std::istream& is, std::string& string, std::size_t length)
{
    string.resize(length);
    return is.read(&string[0], string.size());
}

template <typename T, std::size_t N = sizeof(T)>
std::ostream& write(std::ostream& os, const T& x)
{
    static_assert(N <= sizeof(T), "write requires input type to have at least N bytes");

    // We make no assumption about platform endianness.
    for (std::size_t index = 0; index < N; index++)
        os.put(lsb(x >> (8 * index)));

    return os;
}

enum class Signature : uint32
{
    LOCAL_FILE_HEADER        = 0x04034b50,
    CENTRAL_DIRECTORY_HEADER = 0x02014b50,
    ZIP64_EOCD               = 0x06064b50,
    ZIP64_EOCD_LOCATOR       = 0x07064b50,
    EOCD                     = 0x06054b50
};

bool checkSignature(std::istream& is, const Signature& signature)
{
    uint32 sig;
    return read(is, sig) && sig == static_cast<uint32>(signature);
}

uint64 findCentralDirectoryOffset(std::istream& is)
{
    uint64 centralDirectoryOffset;

    // find end of central directory signature
    {
        uint32 signature;
        uint16 commentLength = 0;
        do
        {
            is.seekg(-22 - commentLength, std::ios::end);
        } while (read(is, signature) && signature != static_cast<uint32>(Signature::EOCD) &&
                 commentLength++ < MASK_0_16);

        if (!is || signature != static_cast<uint32>(Signature::EOCD))
            throw Zip::Error("could not find end of central directory signature");
    }

    // read end of central directory record
    {
        uint16 disk;

        read(is, disk);
        is.seekg(10, std::ios::cur);
        read<uint64, 4>(is, centralDirectoryOffset);

        if (!is)
            throw Zip::Error("could not read end of central directory record");
        if (disk != 0)
            throw Zip::Error("split zip archives are not supported");
    }

    // look for Zip64 end of central directory locator
    is.seekg(-40, std::ios::cur);
    if (checkSignature(is, Signature::ZIP64_EOCD_LOCATOR))
    {
        uint64 zip64EndOfCentralDirectoryOffset;

        is.seekg(4, std::ios::cur);
        read(is, zip64EndOfCentralDirectoryOffset);

        if (!is)
            throw Zip::Error("could not read Zip64 end of central directory locator record");

        // read Zip64 end of central directory record
        is.seekg(zip64EndOfCentralDirectoryOffset, std::ios::beg);
        if (checkSignature(is, Signature::ZIP64_EOCD))
        {
            uint16 versionNeededToExtract;

            is.seekg(10, std::ios::cur);
            read(is, versionNeededToExtract);
            is.seekg(32, std::ios::cur);
            read(is, centralDirectoryOffset);

            if (!is)
                throw Zip::Error("could not read Zip64 end of central directory record");
            if (versionNeededToExtract >= 62) // Version 6.2 introduces central directory encryption.
                throw Zip::Error("central directory encryption is not supported");
        }
        else
            throw Zip::Error("could not find Zip64 end of central directory record");
    }

    return centralDirectoryOffset;
}

} // namespace

Zip::Error::Error(const std::string& description)
: BaseError("Zip error", description)
{
}

Zip::Iterator::Iterator(const Zip& archive)
: m_is{&archive.m_is.seekg(archive.m_centralDirectoryOffset, std::ios::beg)}
, m_entry{Entry{}}
{
    ++(*this);
}

Zip::Iterator& Zip::Iterator::operator++()
{
    if (!checkSignature(*m_is, Signature::CENTRAL_DIRECTORY_HEADER))
        return *this = Iterator{};

    uint16 flags;
    uint16 method;
    uint16 lastModTime;
    uint16 lastModDate;

    uint16 filenameLength;
    uint16 extraFieldLength;
    uint16 fileCommentLength;

    m_is->seekg(4, std::ios::cur);
    read(*m_is, flags);
    read(*m_is, method);
    read(*m_is, lastModTime);
    read(*m_is, lastModDate);
    read(*m_is, m_entry->crc32);
    read<uint64, 4>(*m_is, m_entry->packedSize);
    read<uint64, 4>(*m_is, m_entry->uncompressedSize);
    read(*m_is, filenameLength);
    read(*m_is, extraFieldLength);
    read(*m_is, fileCommentLength);
    m_is->seekg(8, std::ios::cur);
    read<uint64, 4>(*m_is, m_entry->offset);
    read(*m_is, m_entry->name, filenameLength);

    m_entry->encryption = flags & 1
                              ? method == 99 || (flags >> 6) & 1 ? Encryption::Unsupported : Encryption::Traditional
                              : Encryption::None;

    m_entry->compression = static_cast<Compression>(method);

    m_entry->checkByte = (flags >> 3) & 1 ? static_cast<byte>(lastModTime >> 8) : msb(m_entry->crc32);

    for (int remaining = extraFieldLength; remaining > 0;)
    {
        // read extra field header
        uint16 id;
        uint16 size;
        read(*m_is, id);
        read(*m_is, size);
        remaining -= 4 + size;

        switch (id)
        {
        case 0x0001: // Zip64 extended information
            if (8 <= size && m_entry->uncompressedSize == MASK_0_32)
            {
                read(*m_is, m_entry->uncompressedSize);
                size -= 8;
            }
            if (8 <= size && m_entry->packedSize == MASK_0_32)
            {
                read(*m_is, m_entry->packedSize);
                size -= 8;
            }
            if (8 <= size && m_entry->offset == MASK_0_32)
            {
                read(*m_is, m_entry->offset);
                size -= 8;
            }
            break;

        case 0x7075: // Info-ZIP Unicode Path
            if (5 <= size)
            {
                uint32 nameCrc32 = MASK_0_32;
                for (byte b : m_entry->name)
                    nameCrc32 = Crc32Tab::crc32(nameCrc32, b);
                nameCrc32 ^= MASK_0_32;

                uint32 expectedNameCrc32;
                m_is->seekg(1, std::ios::cur);
                read(*m_is, expectedNameCrc32);
                size -= 5;

                if (nameCrc32 == expectedNameCrc32)
                {
                    read(*m_is, m_entry->name, size);
                    size = 0;
                }
            }
            break;

        case 0x9901: // AE-x encryption structure
            if (7 <= size)
            {
                uint16 method;
                m_is->seekg(5, std::ios::cur);
                read(*m_is, method);
                size -= 7;

                m_entry->compression = static_cast<Compression>(method);
            }
            break;

        default:
            break;
        }

        // jump to the end of this data block
        m_is->seekg(size, std::ios::cur);
    }

    m_is->seekg(fileCommentLength, std::ios::cur);

    if (!*m_is)
        throw Error("could not read central directory header");

    return *this;
}

Zip::Iterator Zip::Iterator::operator++(int)
{
    auto copy = *this;
    ++(*this);
    return copy;
}

Zip::Zip(std::istream& stream)
: m_file{}
, m_is{stream}
, m_centralDirectoryOffset{findCentralDirectoryOffset(m_is)}
{
}

Zip::Zip(const std::string& filename)
: m_file{openInput(filename)}
, m_is{*m_file}
, m_centralDirectoryOffset{findCentralDirectoryOffset(m_is)}
{
}

Zip::Entry Zip::operator[](const std::string& name) const
{
    const auto it = std::find_if(begin(), end(), [&name](const Entry& entry) { return entry.name == name; });

    if (it == end())
        throw Error("found no entry named \"" + name + "\"");
    else
        return *it;
}

Zip::Entry Zip::operator[](std::size_t index) const
{
    std::size_t nextIndex = 0;
    const auto  it = std::find_if(begin(), end(), [&nextIndex, index](const Entry&) { return nextIndex++ == index; });

    if (it == end())
        throw Error("found no entry at index " + std::to_string(index) + " (maximum index for this archive is " +
                    std::to_string(nextIndex - 1) + ")");
    else
        return *it;
}

void Zip::checkEncryption(const Entry& entry, Encryption expected)
{
    if (entry.encryption != expected)
    {
        if (entry.encryption == Encryption::None)
            throw Error("entry \"" + entry.name + "\" is not encrypted");
        else if (expected == Encryption::None)
            throw Error("entry \"" + entry.name + "\" is encrypted");
        else
            throw Error("entry \"" + entry.name + "\" is encrypted with an unsupported algorithm");
    }
}

std::istream& Zip::seek(const Entry& entry) const
{
    m_is.seekg(entry.offset, std::ios::beg);
    if (!checkSignature(m_is, Signature::LOCAL_FILE_HEADER))
        throw Error("could not find local file header");

    // skip local file header
    uint16 nameSize, extraSize;
    m_is.seekg(22, std::ios::cur);
    read(m_is, nameSize);
    read(m_is, extraSize);
    m_is.seekg(nameSize + extraSize, std::ios::cur);

    return m_is;
}

bytevec Zip::load(const Entry& entry, std::size_t count) const
{
    return loadStream(seek(entry), std::min(entry.packedSize, static_cast<uint64>(count)));
}

void Zip::changeKeys(std::ostream& os, const Keys& oldKeys, const Keys& newKeys, Progress& progress) const
{
    // Store encrypted entries local file header offset and packed size.
    // Use std::map to sort them by local file header offset.
    std::map<uint64, uint64> packedSizeByLocalOffset;
    for (const auto& entry : *this)
        if (entry.encryption == Encryption::Traditional)
            packedSizeByLocalOffset.insert({entry.offset, entry.packedSize});

    // Rewind input stream and iterate on encrypted entries to change the keys, copy the rest.
    m_is.seekg(0, std::ios::beg);
    uint64 currentOffset = 0;

    progress.done  = 0;
    progress.total = packedSizeByLocalOffset.size();

    for (const auto& [localHeaderOffset, packedSize] : packedSizeByLocalOffset)
    {
        if (currentOffset < localHeaderOffset)
        {
            std::copy_n(std::istreambuf_iterator<char>(m_is), localHeaderOffset - currentOffset,
                        std::ostreambuf_iterator<char>(os));
            m_is.get();
        }

        if (!checkSignature(m_is, Signature::LOCAL_FILE_HEADER))
            throw Error("could not find local file header");

        write(os, static_cast<uint32>(Signature::LOCAL_FILE_HEADER));

        std::copy_n(std::istreambuf_iterator<char>(m_is), 22, std::ostreambuf_iterator<char>(os));
        m_is.get();

        uint16 filenameLength, extraSize;
        read(m_is, filenameLength);
        read(m_is, extraSize);
        write(os, filenameLength);
        write(os, extraSize);

        if (0 < filenameLength + extraSize)
        {
            std::copy_n(std::istreambuf_iterator<char>(m_is), filenameLength + extraSize,
                        std::ostreambuf_iterator<char>(os));
            m_is.get();
        }

        Keys                           decrypt = oldKeys;
        Keys                           encrypt = newKeys;
        std::istreambuf_iterator<char> in(m_is);
        std::generate_n(std::ostreambuf_iterator<char>(os), packedSize,
                        [&in, &decrypt, &encrypt]() -> char
                        {
                            byte p = *in++ ^ decrypt.getK();
                            byte c = p ^ encrypt.getK();
                            decrypt.update(p);
                            encrypt.update(p);
                            return c;
                        });

        currentOffset = localHeaderOffset + 30 + filenameLength + extraSize + packedSize;

        progress.done++;
    }

    std::copy(std::istreambuf_iterator<char>(m_is), std::istreambuf_iterator<char>(),
              std::ostreambuf_iterator<char>(os));
}
