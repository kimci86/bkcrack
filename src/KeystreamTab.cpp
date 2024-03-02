#include "KeystreamTab.hpp"

const KeystreamTab KeystreamTab::instance;

KeystreamTab::KeystreamTab()
{
    for (auto z_2_16 = std::uint32_t{}; z_2_16 < 1 << 16; z_2_16 += 4)
    {
        const auto k = lsb((z_2_16 | 2) * (z_2_16 | 3) >> 8);

        keystreamtab[z_2_16 >> 2] = k;
        keystreaminvfiltertab[k][z_2_16 >> 10].push_back(z_2_16);
        keystreaminvexists[k].set(z_2_16 >> 10);
    }
}
