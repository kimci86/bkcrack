#include "Zip.hpp"

#include "Data.hpp"
#include "file.hpp"

#include <algorithm>
#include <iterator>
#include <map>
#include <numeric>
#include <variant>

namespace
{

template <typename T>
auto readInt(std::istream& is) -> T
{
    // We make no assumption about platform endianness.
    auto x = T{};
    for (auto index = std::size_t{}; index < sizeof(T); index++)
        x |= static_cast<T>(is.get()) << (8 * index);

    return x;
}

template <typename T>
void writeInt(std::ostream& os, const T& x)
{
    // We make no assumption about platform endianness.
    for (auto index = std::size_t{}; index < sizeof(T); index++)
        os.put(lsb(x >> (8 * index)));
}

auto readString(std::istream& is, std::size_t length) -> std::string
{
    auto string = std::string{};
    string.resize(length);
    is.read(string.data(), string.size());
    return string;
}

void writeString(std::ostream& os, const std::string& string)
{
    os.write(string.data(), string.size());
}

struct LocalFileHeader;
struct CentralDirectoryHeader;

struct ExtraField
{
    struct Aes
    {
        static constexpr auto headerId = std::uint16_t{0x9901};

        static constexpr auto getDataSize() -> std::uint16_t
        {
            return 7;
        }

        std::uint16_t version;
        std::uint16_t vendor;
        std::uint8_t  strength;
        std::uint16_t method;

        static auto read(std::istream& is, std::uint16_t dataSize) -> Aes
        {
            auto data = Aes{};
            if (dataSize == getDataSize())
            {
                data.version  = readInt<std::uint16_t>(is);
                data.vendor   = readInt<std::uint16_t>(is);
                data.strength = readInt<std::uint8_t>(is);
                data.method   = readInt<std::uint16_t>(is);
            }
            if (!is || dataSize != getDataSize())
                throw Zip::Error{"could not read AES extra field"};
            return data;
        }

        void writeData(std::ostream& os) const
        {
            writeInt(os, version);
            writeInt(os, vendor);
            writeInt(os, strength);
            writeInt(os, method);
        }
    };

    struct InfoZipUnicodePath
    {
        static constexpr auto headerId = std::uint16_t{0x7075};

        auto getDataSize() const -> std::uint16_t
        {
            return 5 + unicodeName.size();
        }

        std::uint8_t  version;
        std::uint32_t nameCrc32;
        std::string   unicodeName;

        static auto read(std::istream& is, std::uint16_t dataSize) -> InfoZipUnicodePath
        {
            auto data = InfoZipUnicodePath{};
            if (5 <= dataSize)
            {
                data.version     = readInt<std::uint8_t>(is);
                data.nameCrc32   = readInt<std::uint32_t>(is);
                data.unicodeName = readString(is, dataSize - 5);
            }
            if (!is || dataSize != data.getDataSize())
                throw Zip::Error{"could not read Info-Zip Unicode Path extra field"};
            return data;
        }

        void writeData(std::ostream& os) const
        {
            writeInt(os, version);
            writeInt(os, nameCrc32);
            writeString(os, unicodeName);
        }
    };

    struct Zip64
    {
        static constexpr auto headerId = std::uint16_t{0x0001};

        auto getDataSize() const -> std::uint16_t
        {
            return (uncompressedSize ? 8 : 0) + (compressedSize ? 8 : 0) + (headerOffset ? 8 : 0) +
                   (diskStartNumber ? 4 : 0);
        }

        std::optional<std::uint64_t> uncompressedSize;
        std::optional<std::uint64_t> compressedSize;
        std::optional<std::uint64_t> headerOffset;
        std::optional<std::uint32_t> diskStartNumber;

        template <typename Header, typename = std::enable_if_t<std::is_same_v<Header, LocalFileHeader> ||
                                                               std::is_same_v<Header, CentralDirectoryHeader>>>
        static auto read(std::istream& is, std::uint16_t dataSize, const Header& header) -> Zip64
        {
            auto data      = Zip64{};
            auto remaining = dataSize;
            if (8 <= remaining && header.uncompressedSize == mask<0, 32>)
            {
                data.uncompressedSize = readInt<std::uint64_t>(is);
                remaining -= 8;
            }
            if (8 <= remaining && header.compressedSize == mask<0, 32>)
            {
                data.compressedSize = readInt<std::uint64_t>(is);
                remaining -= 8;
            }
            if constexpr (std::is_same_v<Header, CentralDirectoryHeader>)
            {
                if (8 <= remaining && header.headerOffset == mask<0, 32>)
                {
                    data.headerOffset = readInt<std::uint64_t>(is);
                    remaining -= 8;
                }
                if (4 <= remaining && header.diskStartNumber == mask<0, 16>)
                {
                    data.diskStartNumber = readInt<std::uint32_t>(is);
                    remaining -= 4;
                }
            }

            if (!is || dataSize != data.getDataSize())
                throw Zip::Error{"could not read ZIP64 extra field"};

            return data;
        }

        void writeData(std::ostream& os) const
        {
            if (uncompressedSize)
                writeInt(os, *uncompressedSize);
            if (compressedSize)
                writeInt(os, *compressedSize);
            if (headerOffset)
                writeInt(os, *headerOffset);
            if (diskStartNumber)
                writeInt(os, *diskStartNumber);
        }
    };

    struct Other
    {
        std::uint16_t headerId;

        auto getDataSize() const -> std::uint16_t
        {
            return data.size();
        }

        std::string data;

        static auto read(std::istream& is, std::uint16_t headerId, std::uint16_t dataSize) -> Other
        {
            auto data = Other{headerId, readString(is, dataSize)};
            if (!is || dataSize != data.getDataSize())
                throw Zip::Error{"could not read extra field"};
            return data;
        }

        void writeData(std::ostream& os) const
        {
            writeString(os, data);
        }
    };

    template <typename Header, typename = std::enable_if_t<std::is_same_v<Header, LocalFileHeader> ||
                                                           std::is_same_v<Header, CentralDirectoryHeader>>>
    static auto read(std::istream& is, const Header& header) -> ExtraField
    {
        auto extraField = ExtraField{};
        auto remaining  = header.extraFieldLength;
        while (remaining)
        {
            if (remaining < 4)
                throw Zip::Error{"could not read extra field"};

            const auto headerId = readInt<std::uint16_t>(is);
            const auto dataSize = readInt<std::uint16_t>(is);
            remaining -= 4;

            if (!is || remaining < dataSize)
                throw Zip::Error{"could not read extra field"};

            switch (headerId)
            {
            case Aes::headerId:
                extraField.blocks.emplace_back(Aes::read(is, dataSize));
                break;
            case InfoZipUnicodePath::headerId:
                extraField.blocks.emplace_back(InfoZipUnicodePath::read(is, dataSize));
                break;
            case Zip64::headerId:
                extraField.blocks.emplace_back(Zip64::read(is, dataSize, header));
                break;
            default:
                extraField.blocks.emplace_back(Other::read(is, headerId, dataSize));
                break;
            }
            remaining -= dataSize;
        }
        return extraField;
    }

    void write(std::ostream& os) const
    {
        for (const auto& block : blocks)
            std::visit(
                [&os](const auto& block)
                {
                    writeInt(os, block.headerId);
                    writeInt(os, block.getDataSize());
                    block.writeData(os);
                },
                block);
    }

    template <typename T>
    auto find() const -> const T*
    {
        const auto it = std::find_if(blocks.begin(), blocks.end(),
                                     [](const auto& block) { return std::holds_alternative<T>(block); });
        return it != blocks.end() ? &std::get<T>(*it) : nullptr;
    }

    template <typename T>
    auto find() -> T*
    {
        const auto it = std::find_if(blocks.begin(), blocks.end(),
                                     [](const auto& block) { return std::holds_alternative<T>(block); });
        return it != blocks.end() ? &std::get<T>(*it) : nullptr;
    }

    std::vector<std::variant<Aes, InfoZipUnicodePath, Zip64, Other>> blocks;
};

struct LocalFileHeader
{
    std::uint16_t versionNeededToExtract;
    std::uint16_t flags;
    std::uint16_t method;
    std::uint16_t lastModTime;
    std::uint16_t lastModDate;
    std::uint32_t crc32;
    std::uint32_t compressedSize;
    std::uint32_t uncompressedSize;
    std::uint16_t filenameLength;
    std::uint16_t extraFieldLength;
    std::string   filename;
    ExtraField    extraField;

    static auto read(std::istream& is) -> LocalFileHeader
    {
        auto header                   = LocalFileHeader{};
        header.versionNeededToExtract = readInt<std::uint16_t>(is);
        header.flags                  = readInt<std::uint16_t>(is);
        header.method                 = readInt<std::uint16_t>(is);
        header.lastModTime            = readInt<std::uint16_t>(is);
        header.lastModDate            = readInt<std::uint16_t>(is);
        header.crc32                  = readInt<std::uint32_t>(is);
        header.compressedSize         = readInt<std::uint32_t>(is);
        header.uncompressedSize       = readInt<std::uint32_t>(is);
        header.filenameLength         = readInt<std::uint16_t>(is);
        header.extraFieldLength       = readInt<std::uint16_t>(is);
        header.filename               = readString(is, header.filenameLength);
        header.extraField             = ExtraField::read(is, header);

        if (!is)
            throw Zip::Error{"could not read local file header"};

        return header;
    }

    void write(std::ostream& os) const
    {
        writeInt(os, versionNeededToExtract);
        writeInt(os, flags);
        writeInt(os, method);
        writeInt(os, lastModTime);
        writeInt(os, lastModDate);
        writeInt(os, crc32);
        writeInt(os, compressedSize);
        writeInt(os, uncompressedSize);
        writeInt(os, filenameLength);
        writeInt(os, extraFieldLength);
        writeString(os, filename);
        extraField.write(os);
    }
};

struct CentralDirectoryHeader
{
    std::uint16_t versionMadeBy;
    std::uint16_t versionNeededToExtract;
    std::uint16_t flags;
    std::uint16_t method;
    std::uint16_t lastModTime;
    std::uint16_t lastModDate;
    std::uint32_t crc32;
    std::uint32_t compressedSize;
    std::uint32_t uncompressedSize;
    std::uint16_t filenameLength;
    std::uint16_t extraFieldLength;
    std::uint16_t fileCommentLength;
    std::uint16_t diskStartNumber;
    std::uint16_t internalFileAttributes;
    std::uint32_t externalFileAttributes;
    std::uint32_t headerOffset;
    std::string   filename;
    ExtraField    extraField;
    std::string   fileComment;

    static auto read(std::istream& is) -> CentralDirectoryHeader
    {
        auto header                   = CentralDirectoryHeader{};
        header.versionMadeBy          = readInt<std::uint16_t>(is);
        header.versionNeededToExtract = readInt<std::uint16_t>(is);
        header.flags                  = readInt<std::uint16_t>(is);
        header.method                 = readInt<std::uint16_t>(is);
        header.lastModTime            = readInt<std::uint16_t>(is);
        header.lastModDate            = readInt<std::uint16_t>(is);
        header.crc32                  = readInt<std::uint32_t>(is);
        header.compressedSize         = readInt<std::uint32_t>(is);
        header.uncompressedSize       = readInt<std::uint32_t>(is);
        header.filenameLength         = readInt<std::uint16_t>(is);
        header.extraFieldLength       = readInt<std::uint16_t>(is);
        header.fileCommentLength      = readInt<std::uint16_t>(is);
        header.diskStartNumber        = readInt<std::uint16_t>(is);
        header.internalFileAttributes = readInt<std::uint16_t>(is);
        header.externalFileAttributes = readInt<std::uint32_t>(is);
        header.headerOffset           = readInt<std::uint32_t>(is);
        header.filename               = readString(is, header.filenameLength);
        header.extraField             = ExtraField::read(is, header);
        header.fileComment            = readString(is, header.fileCommentLength);

        if (!is)
            throw Zip::Error{"could not read central directory header"};

        return header;
    }

    void write(std::ostream& os) const
    {
        writeInt(os, versionMadeBy);
        writeInt(os, versionNeededToExtract);
        writeInt(os, flags);
        writeInt(os, method);
        writeInt(os, lastModTime);
        writeInt(os, lastModDate);
        writeInt(os, crc32);
        writeInt(os, compressedSize);
        writeInt(os, uncompressedSize);
        writeInt(os, filenameLength);
        writeInt(os, extraFieldLength);
        writeInt(os, fileCommentLength);
        writeInt(os, diskStartNumber);
        writeInt(os, internalFileAttributes);
        writeInt(os, externalFileAttributes);
        writeInt(os, headerOffset);
        writeString(os, filename);
        extraField.write(os);
        writeString(os, fileComment);
    }

    auto getEncryption() const -> Zip::Encryption
    {
        return flags & 1
                   ? method == 99 || (flags >> 6) & 1 ? Zip::Encryption::Unsupported : Zip::Encryption::Traditional
                   : Zip::Encryption::None;
    }
};

enum class Signature : std::uint32_t
{
    LocalFileHeader        = 0x04034b50,
    DataDescriptor         = 0x08074b50,
    CentralDirectoryHeader = 0x02014b50,
    Zip64Eocd              = 0x06064b50,
    Zip64EocdLocator       = 0x07064b50,
    Eocd                   = 0x06054b50
};

auto checkSignature(std::istream& is, const Signature& signature) -> bool
{
    const auto sig = readInt<std::uint32_t>(is);
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
            signature = readInt<std::uint32_t>(is);
        } while (is && signature != static_cast<std::uint32_t>(Signature::Eocd) && commentLength++ < mask<0, 16>);

        if (!is || signature != static_cast<std::uint32_t>(Signature::Eocd))
            throw Zip::Error{"could not find end of central directory signature"};
    }

    // read end of central directory record
    {
        const auto disk = readInt<std::uint16_t>(is);
        is.seekg(10, std::ios::cur);
        centralDirectoryOffset = readInt<std::uint32_t>(is);

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
        const auto zip64EndOfCentralDirectoryOffset = readInt<std::uint64_t>(is);

        if (!is)
            throw Zip::Error{"could not read Zip64 end of central directory locator record"};

        // read Zip64 end of central directory record
        is.seekg(zip64EndOfCentralDirectoryOffset, std::ios::beg);
        if (checkSignature(is, Signature::Zip64Eocd))
        {
            is.seekg(10, std::ios::cur);
            const auto versionNeededToExtract = readInt<std::uint16_t>(is);
            is.seekg(32, std::ios::cur);
            centralDirectoryOffset = readInt<std::uint64_t>(is);

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

    const auto header = CentralDirectoryHeader::read(*m_is);

    const auto* aesExtraData = header.extraField.find<ExtraField::Aes>();
    const auto* unicodePath  = header.extraField.find<ExtraField::InfoZipUnicodePath>();
    const auto* zip64        = header.extraField.find<ExtraField::Zip64>();

    m_entry->name =
        (unicodePath && (std::accumulate(header.filename.begin(), header.filename.end(), mask<0, 32>, Crc32Tab::crc32) ^
                         mask<0, 32>) == unicodePath->nameCrc32)
            ? unicodePath->unicodeName
            : header.filename;
    m_entry->encryption       = header.getEncryption();
    m_entry->compression      = static_cast<Zip::Compression>(aesExtraData ? aesExtraData->method : header.method);
    m_entry->crc32            = header.crc32;
    m_entry->offset           = zip64 && zip64->headerOffset ? *zip64->headerOffset : header.headerOffset;
    m_entry->packedSize       = zip64 && zip64->compressedSize ? *zip64->compressedSize : header.compressedSize;
    m_entry->uncompressedSize = zip64 && zip64->uncompressedSize ? *zip64->uncompressedSize : header.uncompressedSize;
    m_entry->checkByte        = (header.flags >> 3) & 1 ? lsb(header.lastModTime >> 8) : msb(header.crc32);

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
    const auto nameSize  = readInt<std::uint16_t>(m_is);
    const auto extraSize = readInt<std::uint16_t>(m_is);
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

        writeInt(os, static_cast<std::uint32_t>(Signature::LocalFileHeader));

        std::copy_n(std::istreambuf_iterator{m_is}, 22, std::ostreambuf_iterator{os});
        m_is.get();

        const auto filenameLength = readInt<std::uint16_t>(m_is);
        const auto extraSize      = readInt<std::uint16_t>(m_is);
        writeInt(os, filenameLength);
        writeInt(os, extraSize);

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

void Zip::decrypt(std::ostream& os, const Keys& keys, Progress& progress) const
{
    // Store encrypted entries local file header offset and packed size.
    // Use std::map to sort them by local file header offset.
    auto packedSizeByLocalOffset = std::map<std::uint64_t, std::uint64_t>{};
    for (const auto& entry : *this)
        if (entry.encryption == Encryption::Traditional)
            packedSizeByLocalOffset.insert({entry.offset, entry.packedSize});

    // Rewind input stream and iterate on encrypted entries to decipher data and update related metadata.
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

        // transform file header
        if (!checkSignature(m_is, Signature::LocalFileHeader))
            throw Error{"could not find local file header"};
        writeInt(os, static_cast<std::uint32_t>(Signature::LocalFileHeader));

        auto  fileHeader     = LocalFileHeader::read(m_is);
        auto* zip64ExtraData = fileHeader.extraField.find<ExtraField::Zip64>();
        fileHeader.flags &= ~1;
        if (zip64ExtraData && zip64ExtraData->compressedSize)
            *zip64ExtraData->compressedSize -= Data::encryptionHeaderSize;
        else if (Data::encryptionHeaderSize <= fileHeader.compressedSize)
            fileHeader.compressedSize -= Data::encryptionHeaderSize;
        fileHeader.write(os);

        // decipher file data
        decipher(m_is, packedSize, Data::encryptionHeaderSize, os, keys);

        // transform data descriptor
        auto dataDescriptorSize = 0;
        if ((fileHeader.flags >> 3) & 1)
        {
            // optional signature + crc-32
            const auto crc32OrSignature = readInt<std::uint32_t>(m_is);
            writeInt<std::uint32_t>(os, crc32OrSignature);
            dataDescriptorSize += 4;

            if (crc32OrSignature == static_cast<std::uint32_t>(Signature::DataDescriptor))
            {
                const auto actualCrc32 = readInt<std::uint32_t>(m_is);
                writeInt<std::uint32_t>(os, actualCrc32);
                dataDescriptorSize += 4;
            }

            // compressed size, uncompressed size
            if (zip64ExtraData)
            {
                writeInt<std::uint64_t>(os, readInt<std::uint64_t>(m_is) - Data::encryptionHeaderSize);
                writeInt<std::uint64_t>(os, readInt<std::uint64_t>(m_is));
                dataDescriptorSize += 8 + 8;
            }
            else
            {
                writeInt<std::uint32_t>(os, readInt<std::uint32_t>(m_is) - Data::encryptionHeaderSize);
                writeInt<std::uint32_t>(os, readInt<std::uint32_t>(m_is));
                dataDescriptorSize += 4 + 4;
            }
        }

        currentOffset = localHeaderOffset + 30 + fileHeader.filenameLength + fileHeader.extraFieldLength + packedSize +
                        dataDescriptorSize;

        progress.done++;
    }

    if (currentOffset < m_centralDirectoryOffset)
    {
        std::copy_n(std::istreambuf_iterator{m_is}, m_centralDirectoryOffset - currentOffset,
                    std::ostreambuf_iterator{os});
        m_is.get();
        currentOffset = m_centralDirectoryOffset;
    }

    const auto translateOffset = [&packedSizeByLocalOffset](auto offset)
    {
        return offset - std::distance(packedSizeByLocalOffset.begin(), packedSizeByLocalOffset.lower_bound(offset)) *
                            Data::encryptionHeaderSize;
    };

    // update metadata in central directory
    auto signature = readInt<std::uint32_t>(m_is);

    while (m_is && signature == static_cast<std::uint32_t>(Signature::CentralDirectoryHeader))
    {
        writeInt<std::uint32_t>(os, signature);

        auto  centralDirectoryHeader = CentralDirectoryHeader::read(m_is);
        auto* zip64ExtraData         = centralDirectoryHeader.extraField.find<ExtraField::Zip64>();
        if (centralDirectoryHeader.getEncryption() == Zip::Encryption::Traditional)
        {
            centralDirectoryHeader.flags &= ~1;
            if (zip64ExtraData && zip64ExtraData->compressedSize)
                *zip64ExtraData->compressedSize -= Data::encryptionHeaderSize;
            else if (Data::encryptionHeaderSize <= centralDirectoryHeader.compressedSize)
                centralDirectoryHeader.compressedSize -= Data::encryptionHeaderSize;
        }
        if (zip64ExtraData && zip64ExtraData->headerOffset)
            *zip64ExtraData->headerOffset = translateOffset(*zip64ExtraData->headerOffset);
        else
            centralDirectoryHeader.headerOffset = translateOffset(centralDirectoryHeader.headerOffset);
        centralDirectoryHeader.write(os);

        signature = readInt<std::uint32_t>(m_is);
    }

    auto isZip64 = false;
    if (m_is && signature == static_cast<std::uint32_t>(Signature::Zip64Eocd))
    {
        writeInt<std::uint32_t>(os, signature);
        isZip64 = true;

        const auto sizeOfZip64Eocd = readInt<std::uint64_t>(m_is);
        writeInt<std::uint64_t>(os, sizeOfZip64Eocd);

        std::copy_n(std::istreambuf_iterator{m_is}, 36, std::ostreambuf_iterator{os});
        m_is.get();

        const auto eocdStartOffset = readInt<std::uint64_t>(m_is);
        writeInt<std::uint64_t>(os, translateOffset(eocdStartOffset));

        if (44 < sizeOfZip64Eocd)
        {
            std::copy_n(std::istreambuf_iterator{m_is}, sizeOfZip64Eocd - 44, std::ostreambuf_iterator{os});
            m_is.get();
        }

        if (!checkSignature(m_is, Signature::Zip64EocdLocator))
            throw Error{"could not find Zip64 end of central directory locator"};
        writeInt<std::uint32_t>(os, static_cast<std::uint32_t>(Signature::Zip64EocdLocator));

        std::copy_n(std::istreambuf_iterator{m_is}, 4, std::ostreambuf_iterator{os});
        m_is.get();

        const auto zip64EocdStartOffset = readInt<std::uint64_t>(m_is);
        writeInt<std::uint64_t>(os, translateOffset(zip64EocdStartOffset));

        std::copy_n(std::istreambuf_iterator{m_is}, 4, std::ostreambuf_iterator{os});
        m_is.get();

        signature = readInt<std::uint32_t>(m_is);
    }

    if (!m_is || signature != static_cast<std::uint32_t>(Signature::Eocd))
        throw Error{"could not find end of central directory record"};
    writeInt<std::uint32_t>(os, static_cast<std::uint32_t>(Signature::Eocd));

    std::copy_n(std::istreambuf_iterator{m_is}, 12, std::ostreambuf_iterator{os});
    m_is.get();

    auto eocdOffset = readInt<std::uint32_t>(m_is);
    if (!isZip64 || eocdOffset != mask<0, 32>)
        eocdOffset = translateOffset(eocdOffset);
    writeInt<std::uint32_t>(os, eocdOffset);

    std::copy(std::istreambuf_iterator{m_is}, {}, std::ostreambuf_iterator{os});
}

void decipher(std::istream& is, std::size_t size, std::size_t discard, std::ostream& os, Keys keys)
{
    auto cipher = std::istreambuf_iterator{is};
    auto i      = std::size_t{};

    for (; i < discard && i < size && cipher != std::istreambuf_iterator<char>{}; i++, ++cipher)
        keys.update(*cipher ^ keys.getK());

    for (auto plain = std::ostreambuf_iterator{os}; i < size && cipher != std::istreambuf_iterator<char>{};
         i++, ++cipher, ++plain)
    {
        const auto p = *cipher ^ keys.getK();
        keys.update(p);
        *plain = p;
    }
}
