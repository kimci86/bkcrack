#include "Keys.hpp"

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
    for (auto i = ciphertext.begin() + current; i != ciphertext.begin() + target; ++i)
        update(*i ^ getK());
}

void Keys::updateBackward(const std::vector<std::uint8_t>& ciphertext, std::size_t current, std::size_t target)
{
    for (auto i = std::reverse_iterator{ciphertext.begin() + current};
         i != std::reverse_iterator{ciphertext.begin() + target}; ++i)
        updateBackward(*i);
}
