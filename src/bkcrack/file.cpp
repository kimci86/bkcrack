#include "bkcrack/file.hpp"

#include <algorithm>
#include <ranges>

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
    std::ranges::copy(std::ranges::subrange{std::istreambuf_iterator{is}, std::istreambuf_iterator<char>{}} |
                          std::views::take(size),
                      std::back_inserter(content));

    return content;
}

auto openOutput(const std::string& filename) -> std::ofstream
{
    if (auto os = std::ofstream{filename, std::ios::binary})
        return os;
    else
        throw FileError{"could not open output file " + filename};
}
