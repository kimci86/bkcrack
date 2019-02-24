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
    y = (y + lsb(x)) * MultTab::mult + 1;
    z = Crc32Tab::crc32(z, msb(y));
}

void Keys::updateBackward(byte c)
{
    z = Crc32Tab::crc32inv(z, msb(y));
    y = (y - 1) * MultTab::multinv - lsb(x);
    x = Crc32Tab::crc32inv(x, c ^ KeystreamTab::getByte(z));
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
