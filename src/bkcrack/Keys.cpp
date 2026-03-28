#include "bkcrack/Keys.hpp"

#include <ranges>

Keys::Keys(std::uint32_t x, std::uint32_t y, std::uint32_t z)
: x{x}
, y{y}
, z{z}
{
}

Keys::Keys(const std::string& password)
{
    for (const auto p : password)
        update(p);
}

void Keys::update(const std::vector<std::uint8_t>& ciphertext, std::size_t current, std::size_t target)
{
    for (const auto c : ciphertext | std::views::take(target) | std::views::drop(current))
        update(c ^ getK());
}

void Keys::updateBackward(const std::vector<std::uint8_t>& ciphertext, std::size_t current, std::size_t target)
{
    for (const auto c : ciphertext | std::views::take(current) | std::views::drop(target) | std::views::reverse)
        updateBackward(c);
}
