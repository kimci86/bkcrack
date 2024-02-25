#include "file.hpp"

FileError::FileError(const std::string& description)
: BaseError("File error", description)
{
}

std::ifstream openInput(const std::string& filename)
{
    if (std::ifstream is = std::ifstream(filename, std::ios::binary))
        return is;
    else
        throw FileError("could not open input file " + filename);
}

std::vector<std::uint8_t> loadStream(std::istream& is, std::size_t size)
{
    std::vector<std::uint8_t>      content;
    std::istreambuf_iterator<char> it(is);
    for (std::size_t i = 0; i < size && it != std::istreambuf_iterator<char>(); i++, ++it)
        content.push_back(*it);

    return content;
}

std::vector<std::uint8_t> loadFile(const std::string& filename, std::size_t size)
{
    std::ifstream is = openInput(filename);
    return loadStream(is, size);
}

std::ofstream openOutput(const std::string& filename)
{
    if (std::ofstream os = std::ofstream(filename, std::ios::binary))
        return os;
    else
        throw FileError("could not open output file " + filename);
}
