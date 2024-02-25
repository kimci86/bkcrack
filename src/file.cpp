#include "file.hpp"

FileError::FileError(const std::string& description)
: BaseError{"File error", description}
{
}

auto openInput(const std::string& filename) -> std::ifstream
{
    if (auto is = std::ifstream{filename, std::ios::binary})
        return is;
    else
        throw FileError{"could not open input file " + filename};
}

auto loadStream(std::istream& is, std::size_t size) -> std::vector<std::uint8_t>
{
    auto content = std::vector<std::uint8_t>{};
    auto it      = std::istreambuf_iterator{is};
    for (auto i = std::size_t{}; i < size && it != std::istreambuf_iterator<char>{}; i++, ++it)
        content.push_back(*it);

    return content;
}

auto loadFile(const std::string& filename, std::size_t size) -> std::vector<std::uint8_t>
{
    auto is = openInput(filename);
    return loadStream(is, size);
}

auto openOutput(const std::string& filename) -> std::ofstream
{
    if (auto os = std::ofstream{filename, std::ios::binary})
        return os;
    else
        throw FileError{"could not open output file " + filename};
}
