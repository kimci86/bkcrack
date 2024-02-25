#include "MultTab.hpp"

const MultTab MultTab::instance;

MultTab::MultTab()
{
    std::uint32_t prod    = 0; // x * mult
    std::uint32_t prodinv = 0; // x * mult^-1
    for (int x = 0; x < 256; x++, prod += mult, prodinv += multInv)
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
