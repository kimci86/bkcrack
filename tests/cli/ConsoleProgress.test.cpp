#include "ConsoleProgress.hpp"

#include <TestRunner.hpp>

#include <sstream>

TEST("print progress regularly")
{
    auto oss = std::ostringstream{};
    {
        auto progress  = ConsoleProgress{oss, std::chrono::milliseconds{20}};
        progress.total = 10;
        CHECK(oss.str() == "");

        std::this_thread::sleep_for(std::chrono::milliseconds{500});
        CHECK(oss.str().ends_with("0.0 % (0 / 10)\r              \r"));

        progress.done = 9;
        std::this_thread::sleep_for(std::chrono::milliseconds{500});
        CHECK(oss.str().ends_with("90.0 % (9 / 10)\r               \r"));

        progress.done = 10;
    }
    CHECK(oss.str().ends_with("100.0 % (10 / 10)\n"));
}
