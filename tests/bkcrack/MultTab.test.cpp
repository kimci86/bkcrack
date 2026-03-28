#include <bkcrack/MultTab.hpp>

#include <TestRunner.hpp>

#include <algorithm>

TEST("getMsbProdFiber2")
{
    for (auto msbprodinv = 0; msbprodinv < 256; ++msbprodinv)
    {
        const auto fiber = MultTab::getMsbProdFiber2(msbprodinv);
        for (auto x = 0; x < 256; ++x)
        {
            const auto m               = msb(x * MultTab::multInv);
            const auto expectedInFiber = m == msbprodinv || m == (msbprodinv + 255) % 256;
            const auto actuallyInFiber = std::ranges::find(fiber, x) != fiber.end();
            CHECK(actuallyInFiber == expectedInFiber);
        }
    }
}

TEST("getMsbProdFiber3")
{
    for (auto msbprodinv = 0; msbprodinv < 256; ++msbprodinv)
    {
        const auto fiber = MultTab::getMsbProdFiber3(msbprodinv);
        for (auto x = 0; x < 256; ++x)
        {
            const auto m = msb(x * MultTab::multInv);
            const auto expectedInFiber =
                m == msbprodinv || m == (msbprodinv + 255) % 256 || m == (msbprodinv + 1) % 256;
            const auto actuallyInFiber = std::ranges::find(fiber, x) != fiber.end();
            CHECK(actuallyInFiber == expectedInFiber);
        }
    }
}
