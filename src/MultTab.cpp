#include "MultTab.hpp"

const MultTab MultTab::instance;

MultTab::MultTab()
{
    auto prod    = std::uint32_t{}; // x * mult
    auto prodinv = std::uint32_t{}; // x * mult^-1
    for (auto x = 0; x < 256; x++, prod += mult, prodinv += multInv)
    {
        multtab[x]    = prod;
        multinvtab[x] = prodinv;

        msbprodfiber2[msb(prodinv)].push_back(x);
        msbprodfiber2[(msb(prodinv) + 1) % 256].push_back(x);

        msbprodfiber3[(msb(prodinv) + 255) % 256].push_back(x);
        msbprodfiber3[msb(prodinv)].push_back(x);
        msbprodfiber3[(msb(prodinv) + 1) % 256].push_back(x);
    }
}
