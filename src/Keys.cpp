#include "Keys.hpp"
#include "Crc32Tab.hpp"
#include "KeystreamTab.hpp"
#include "MultTab.hpp"
#include <iomanip>

Keys::Keys(dword x, dword y, dword z)
 : x(x), y(y), z(z)
{}

void Keys::update(byte p)
{
    x = Crc32Tab::crc32(x, p);
    y = (y + lsb(x)) * MultTab::MULT + 1;
    z = Crc32Tab::crc32(z, msb(y));
}

void Keys::update(const bytevec& ciphertext, std::size_t current, std::size_t target)
{
    for(bytevec::const_iterator i = ciphertext.begin() + current; i != ciphertext.begin() + target; ++i)
        update(*i ^ KeystreamTab::getByte(z));
}

void Keys::updateBackward(byte c)
{
    z = Crc32Tab::crc32inv(z, msb(y));
    y = (y - 1) * MultTab::MULTINV - lsb(x);
    x = Crc32Tab::crc32inv(x, c ^ KeystreamTab::getByte(z));
}

void Keys::updateBackward(const bytevec& ciphertext, std::size_t current, std::size_t target)
{
    using rit = std::reverse_iterator<bytevec::const_iterator>;

    for(rit i = rit(ciphertext.begin() + current); i != rit(ciphertext.begin() + target); ++i)
        updateBackward(*i);
}

dword Keys::getX() const
{
    return x;
}

dword Keys::getY() const
{
    return y;
}

dword Keys::getZ() const
{
    return z;
}

std::ostream& operator<<(std::ostream& os, const Keys& keys)
{
    return os << std::hex
              << std::setw(8) << keys.getX() << " "
              << std::setw(8) << keys.getY() << " "
              << std::setw(8) << keys.getZ() << " "
              << std::dec;
}
