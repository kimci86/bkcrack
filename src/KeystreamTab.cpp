#include "KeystreamTab.hpp"

const KeystreamTab KeystreamTab::instance;

KeystreamTab::KeystreamTab()
{
    for(uint32 z_2_16 = 0; z_2_16 < 1 << 16; z_2_16 += 4)
    {
        byte k = lsb((z_2_16 | 2) * (z_2_16 | 3) >> 8);
        keystreamtab[z_2_16 >> 2] = k;
        keystreaminvfiltertab[k][z_2_16 >> 10].push_back(z_2_16);
        keystreaminvexists[k].set(z_2_16 >> 10);
    }
}
