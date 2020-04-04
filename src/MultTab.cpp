#include "MultTab.hpp"

const MultTab MultTab::instance;

MultTab::MultTab()
{
    dword prodinv = 0; // x * MULT^-1
    for(int x = 0; x < 256; x++, prodinv += MULTINV)
    {
        multinvtab[x] = prodinv;

        msbprodfiber2[msb(prodinv)].push_back(x);
        msbprodfiber2[(msb(prodinv) + 1) % 256].push_back(x);

        msbprodfiber3[(msb(prodinv) + 255) % 256].push_back(x);
        msbprodfiber3[ msb(prodinv)             ].push_back(x);
        msbprodfiber3[(msb(prodinv) +   1) % 256].push_back(x);
    }
}
