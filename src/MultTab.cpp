#include "MultTab.hpp"

const MultTab MultTab::instance;

MultTab::MultTab()
{
    auto prodinv = std::uint32_t{}; // x * mult^-1
    for (auto x = 0; x < 256; x++, prodinv += multInv)
    {
        msbprodfiber2[msb(prodinv)].push_back(x);
        msbprodfiber2[(msb(prodinv) + 1) % 256].push_back(x);

        msbprodfiber3[(msb(prodinv) + 255) % 256].push_back(x);
        msbprodfiber3[msb(prodinv)].push_back(x);
        msbprodfiber3[(msb(prodinv) + 1) % 256].push_back(x);
    }
}
