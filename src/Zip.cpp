#include "Zip.hpp"

#include "file.hpp"

#include <algorithm>
#include <iterator>
#include <map>
#include <numeric>

namespace
{

template <typename T>
auto read(std::istream& is) -> T
{
    // We make no assumption about platform endianness.
    auto x = T{};
    for (auto index = std::size_t{}; index < sizeof(T); index++)
        x |= static_cast<T>(is.get()) << (8 * index);

    return x;
}

auto read(std::istream& is, std::size_t length) -> std::string
{
    auto string = std::string{};
    string.resize(length);
    is.read(string.data(), string.size());
    return string;
}

template <typename T>
auto write(std::ostream& os, const T& x) -> std::ostream&
{
    // We make no assumption about platform endianness.
    for (auto index = std::size_t{}; index < sizeof(T); index++)
        os.put(lsb(x >> (8 * index)));

    return os;
}

enum class Signature : std::uint32_t
{
    LocalFileHeader        = 0x04034b50,
    CentralDirectoryHeader = 0x02014b50,
    Zip64Eocd              = 0x06064b50,
    Zip64EocdLocator       = 0x07064b50,
    Eocd                   = 0x06054b50
};

auto checkSignature(std::istream& is, const Signature& signature) -> bool
{
    const auto sig = read<std::uint32_t>(is);
    return is && sig == static_cast<std::uint32_t>(signature);
}

auto findCentralDirectoryOffset(std::istream& is) -> std::uint64_t
{
    auto centralDirectoryOffset = std::uint64_t{};

    // find end of central directory signature
    {
        auto signature     = std::uint32_t{};
        auto commentLength = std::uint16_t{};
        do
        {
            is.seekg(-22 - commentLength, std::ios::end);
            signature = read<std::uint32_t>(is);
        } while (is && signature != static_cast<std::uint32_t>(Signature::Eocd) && commentLength++ < mask<0, 16>);

        if (!is || signature != static_cast<std::uint32_t>(Signature::Eocd))
            throw Zip::Error{"could not find end of central directory signature"};
    }

    // read end of central directory record
    {
        const auto disk = read<std::uint16_t>(is);
        is.seekg(10, std::ios::cur);
        centralDirectoryOffset = read<std::uint32_t>(is);

        if (!is)
            throw Zip::Error{"could not read end of central directory record"};
        if (disk != 0)
            throw Zip::Error{"split zip archives are not supported"};
    }

    // look for Zip64 end of central directory locator
    is.seekg(-40, std::ios::cur);
    if (checkSignature(is, Signature::Zip64EocdLocator))
    {
        is.seekg(4, std::ios::cur);
        const auto zip64EndOfCentralDirectoryOffset = read<std::uint64_t>(is);

        if (!is)
            throw Zip::Error{"could not read Zip64 end of central directory locator record"};

        // read Zip64 end of central directory record
        is.seekg(zip64EndOfCentralDirectoryOffset, std::ios::beg);
        if (checkSignature(is, Signature::Zip64Eocd))
        {
            is.seekg(10, std::ios::cur);
            const auto versionNeededToExtract = read<std::uint16_t>(is);
            is.seekg(32, std::ios::cur);
            centralDirectoryOffset = read<std::uint64_t>(is);

            if (!is)
                throw Zip::Error{"could not read Zip64 end of central directory record"};
            if (versionNeededToExtract >= 62) // Version 6.2 introduces central directory encryption.
                throw Zip::Error{"central directory encryption is not supported"};
        }
        else
            throw Zip::Error{"could not find Zip64 end of central directory record"};
    }

    return centralDirectoryOffset;
}

} // namespace

Zip::Error::Error(const std::string& description)
: BaseError{"Zip error", description}
{
}

Zip::Iterator::Iterator(const Zip& archive)
: m_is{&archive.m_is.seekg(archive.m_centralDirectoryOffset, std::ios::beg)}
, m_entry{Entry{}}
{
    ++(*this);
}

auto Zip::Iterator::operator++() -> Zip::Iterator&
{
    if (!checkSignature(*m_is, Signature::CentralDirectoryHeader))
        return *this = Iterator{};

    m_is->seekg(4, std::ios::cur);
    const auto flags       = read<std::uint16_t>(*m_is);
    const auto method      = read<std::uint16_t>(*m_is);
    const auto lastModTime = read<std::uint16_t>(*m_is);
    m_is->seekg(2, std::ios::cur);
    m_entry->crc32               = read<std::uint32_t>(*m_is);
    m_entry->packedSize          = read<std::uint32_t>(*m_is);
    m_entry->uncompressedSize    = read<std::uint32_t>(*m_is);
    const auto filenameLength    = read<std::uint16_t>(*m_is);
    const auto extraFieldLength  = read<std::uint16_t>(*m_is);
    const auto fileCommentLength = read<std::uint16_t>(*m_is);
    m_is->seekg(8, std::ios::cur);
    m_entry->offset = read<std::uint32_t>(*m_is);
    m_entry->name   = read(*m_is, filenameLength);

    m_entry->encryption = flags & 1
                              ? method == 99 || (flags >> 6) & 1 ? Encryption::Unsupported : Encryption::Traditional
                              : Encryption::None;

    m_entry->compression = static_cast<Compression>(method);

    m_entry->checkByte = (flags >> 3) & 1 ? static_cast<std::uint8_t>(lastModTime >> 8) : msb(m_entry->crc32);

    for (auto remaining = extraFieldLength; remaining > 0;)
    {
        // read extra field header
        const auto id   = read<std::uint16_t>(*m_is);
        auto       size = read<std::uint16_t>(*m_is);
        remaining -= 4 + size;

        switch (id)
        {
        case 0x0001: // Zip64 extended information
            if (8 <= size && m_entry->uncompressedSize == mask<0, 32>)
            {
                m_entry->uncompressedSize = read<std::uint64_t>(*m_is);
                size -= 8;
            }
            if (8 <= size && m_entry->packedSize == mask<0, 32>)
            {
                m_entry->packedSize = read<std::uint64_t>(*m_is);
                size -= 8;
            }
            if (8 <= size && m_entry->offset == mask<0, 32>)
            {
                m_entry->offset = read<std::uint64_t>(*m_is);
                size -= 8;
            }
            break;

        case 0x7075: // Info-ZIP Unicode Path
            if (5 <= size)
            {
                const auto nameCrc32 =
                    std::accumulate(m_entry->name.begin(), m_entry->name.end(), mask<0, 32>, Crc32Tab::crc32) ^
                    mask<0, 32>;

                m_is->seekg(1, std::ios::cur);
                const auto expectedNameCrc32 = read<std::uint32_t>(*m_is);
                size -= 5;

                if (nameCrc32 == expectedNameCrc32)
                {
                    m_entry->name = read(*m_is, size);
                    size          = 0;
                }
            }
            break;

        case 0x9901: // AE-x encryption structure
            if (7 <= size)
            {
                m_is->seekg(5, std::ios::cur);
                const auto actualMethod = read<std::uint16_t>(*m_is);
                size -= 7;

                m_entry->compression = static_cast<Compression>(actualMethod);
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
        throw Error{"could not read central directory header"};

    return *this;
}

auto Zip::Iterator::operator++(int) -> Zip::Iterator
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

auto Zip::operator[](const std::string& name) const -> Zip::Entry
{
    const auto it = std::find_if(begin(), end(), [&name](const Entry& entry) { return entry.name == name; });

    if (it == end())
        throw Error{"found no entry named \"" + name + "\""};
    else
        return *it;
}

auto Zip::operator[](std::size_t index) const -> Zip::Entry
{
    auto       nextIndex = std::size_t{};
    const auto it = std::find_if(begin(), end(), [&nextIndex, index](const Entry&) { return nextIndex++ == index; });

    if (it == end())
        throw Error{"found no entry at index " + std::to_string(index) + " (maximum index for this archive is " +
                    std::to_string(nextIndex - 1) + ")"};
    else
        return *it;
}

void Zip::checkEncryption(const Entry& entry, Encryption expected)
{
    if (entry.encryption != expected)
    {
        if (entry.encryption == Encryption::None)
            throw Error{"entry \"" + entry.name + "\" is not encrypted"};
        else if (expected == Encryption::None)
            throw Error{"entry \"" + entry.name + "\" is encrypted"};
        else
            throw Error{"entry \"" + entry.name + "\" is encrypted with an unsupported algorithm"};
    }
}

auto Zip::seek(const Entry& entry) const -> std::istream&
{
    m_is.seekg(entry.offset, std::ios::beg);
    if (!checkSignature(m_is, Signature::LocalFileHeader))
        throw Error{"could not find local file header"};

    // skip local file header
    m_is.seekg(22, std::ios::cur);
    const auto nameSize  = read<std::uint16_t>(m_is);
    const auto extraSize = read<std::uint16_t>(m_is);
    m_is.seekg(nameSize + extraSize, std::ios::cur);

    return m_is;
}

auto Zip::load(const Entry& entry, std::size_t count) const -> std::vector<std::uint8_t>
{
    return loadStream(seek(entry), std::min(entry.packedSize, static_cast<std::uint64_t>(count)));
}

void Zip::changeKeys(std::ostream& os, const Keys& oldKeys, const Keys& newKeys, Progress& progress) const
{
    // Store encrypted entries local file header offset and packed size.
    // Use std::map to sort them by local file header offset.
    auto packedSizeByLocalOffset = std::map<std::uint64_t, std::uint64_t>{};
    for (const auto& entry : *this)
        if (entry.encryption == Encryption::Traditional)
            packedSizeByLocalOffset.insert({entry.offset, entry.packedSize});

    // Rewind input stream and iterate on encrypted entries to change the keys, copy the rest.
    m_is.seekg(0, std::ios::beg);
    auto currentOffset = std::uint64_t{};

    progress.done  = 0;
    progress.total = packedSizeByLocalOffset.size();

    for (const auto& [localHeaderOffset, packedSize] : packedSizeByLocalOffset)
    {
        if (currentOffset < localHeaderOffset)
        {
            std::copy_n(std::istreambuf_iterator{m_is}, localHeaderOffset - currentOffset,
                        std::ostreambuf_iterator{os});
            m_is.get();
        }

        if (!checkSignature(m_is, Signature::LocalFileHeader))
            throw Error{"could not find local file header"};

        write(os, static_cast<std::uint32_t>(Signature::LocalFileHeader));

        std::copy_n(std::istreambuf_iterator{m_is}, 22, std::ostreambuf_iterator{os});
        m_is.get();

        const auto filenameLength = read<std::uint16_t>(m_is);
        const auto extraSize      = read<std::uint16_t>(m_is);
        write(os, filenameLength);
        write(os, extraSize);

        if (0 < filenameLength + extraSize)
        {
            std::copy_n(std::istreambuf_iterator{m_is}, filenameLength + extraSize, std::ostreambuf_iterator{os});
            m_is.get();
        }

        auto decrypt = oldKeys;
        auto encrypt = newKeys;
        auto in      = std::istreambuf_iterator{m_is};
        std::generate_n(std::ostreambuf_iterator{os}, packedSize,
                        [&in, &decrypt, &encrypt]() -> char
                        {
                            const auto p = *in++ ^ decrypt.getK();
                            const auto c = p ^ encrypt.getK();
                            decrypt.update(p);
                            encrypt.update(p);
                            return c;
                        });

        currentOffset = localHeaderOffset + 30 + filenameLength + extraSize + packedSize;

        progress.done++;
    }

    std::copy(std::istreambuf_iterator{m_is}, {}, std::ostreambuf_iterator{os});
}
