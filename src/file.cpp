#include "file.hpp"

namespace
{

template <typename T>
void read(std::istream& stream, T& x)
{
    stream.read(reinterpret_cast<char*>(&x), sizeof(x));
}

} // namespace

FileError::FileError(const std::string& description)
 : BaseError("File error", description)
{}

std::ifstream openInput(std::string filename)
{
    if(std::ifstream is = std::ifstream(filename, std::ios::binary))
        return is;
    else
        throw FileError("Could not open input file " + filename);
}

std::ifstream openInputZipEntry(const std::string archivename, const std::string& entryname, std::size_t& size)
{
    std::ifstream is = openInput(archivename);

    // look for end of central directory
    is.seekg(-22, std::ios::end); // start by assuming there is no comment
    dword sig;
    read(is, sig);
    is.seekg(-4, std::ios::cur);
    while(sig != 0x06054b50)
    {
        is.seekg(-1, std::ios::cur);
        read(is, sig);
        is.seekg(-4, std::ios::cur);
    }
    dword eocdoffset = is.tellg(); // end of central directory offset

    // read central directory offset
    dword cdoffset;
    is.seekg(16, std::ios::cur);
    read(is, cdoffset);

    // iterate on each entry
    is.seekg(cdoffset);
    std::string name;
    dword compressedSize, offset;
    while(name != entryname && is.tellg() != eocdoffset)
    {
        name = std::string();
        word nameSize, extraSize, commentSize;

        is.seekg(20, std::ios::cur);
        read(is, compressedSize);
        is.seekg(4, std::ios::cur);
        read(is, nameSize);
        read(is, extraSize);
        read(is, commentSize);
        is.seekg(8, std::ios::cur);
        read(is, offset);
        for(std::size_t i = 0; i < nameSize; i++)
            name.push_back(is.get());
        is.seekg(extraSize + commentSize, std::ios::cur);
    }

    if(name != entryname)
        throw FileError("Could not find " + entryname +" in archive " + archivename);

    // read local file header
    word extraSize;
    is.seekg(offset+28);
    read(is, extraSize);
    is.seekg(name.size() + extraSize, std::ios::cur);

    size = compressedSize;
    return is;
}

std::ofstream openOutput(std::string filename)
{
    if(std::ofstream os = std::ofstream(filename, std::ios::binary))
        return os;
    else
        throw FileError("Could not open output file " + filename);
}

bytevec loadStream(std::istream& is, std::size_t size)
{
    bytevec content;
    std::istreambuf_iterator<char> it(is);
    for(std::size_t i = 0; i < size && it != std::istreambuf_iterator<char>(); i++, ++it)
        content.push_back(*it);

    return content;
}

bytevec loadFile(std::string filename, std::size_t size)
{
    std::ifstream is = openInput(filename);
    return loadStream(is, size);
}

bytevec loadZipEntry(const std::string archivename, const std::string& entryname, std::size_t size)
{
    std::size_t entrysize;
    std::ifstream is = openInputZipEntry(archivename, entryname, entrysize);
    return loadStream(is, std::min(entrysize, size));
}
