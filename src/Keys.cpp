#include "Keys.hpp"

Keys::Keys(uint32 x, uint32 y, uint32 z)
: x(x)
, y(y)
, z(z)
{
}

Keys::Keys(const std::string& password)
: Keys()
{
    for (char p : password)
        update(p);
}

void Keys::update(const bytevec& ciphertext, std::size_t current, std::size_t target)
{
    for (bytevec::const_iterator i = ciphertext.begin() + current; i != ciphertext.begin() + target; ++i)
        update(*i ^ getK());
}

void Keys::updateBackward(const bytevec& ciphertext, std::size_t current, std::size_t target)
{
    using rit = std::reverse_iterator<bytevec::const_iterator>;

    for (rit i = rit(ciphertext.begin() + current); i != rit(ciphertext.begin() + target); ++i)
        updateBackward(*i);
}
