#include <bkcrack/Keys.hpp>
#include <bkcrack/Zreduction.hpp>

#include <TestRunner.hpp>

#include <algorithm>
#include <sstream>

namespace
{
auto makeKeystream(std::size_t length) -> std::vector<std::uint8_t>
{
    auto keystream = std::vector<std::uint8_t>{};
    auto keys      = Keys{"password"};
    for (auto i = 0u; i < length; ++i)
    {
        keystream.emplace_back(keys.getK());
        keys.update('A');
    }
    return keystream;
}

auto getZvalue(std::size_t index) -> std::uint32_t
{
    auto keys = Keys{"password"};
    for (auto i = 0u; i < index; ++i)
        keys.update('A');
    return keys.getZ();
}

auto contains(const std::vector<std::uint32_t>& vector, std::uint32_t value) -> bool
{
    return std::ranges::find(vector, value) != vector.end();
}
} // namespace

TEST("generate only")
{
    const auto keystream = makeKeystream(8);
    const auto z7        = getZvalue(7);

    auto zreduction = Zreduction{keystream};
    CHECK(zreduction.getCandidates().size() == 2'752'512);
    CHECK(zreduction.getIndex() == 7);
    CHECK(contains(zreduction.getCandidates(), z7 & mask<10, 32>));

    zreduction.generate();
    CHECK(zreduction.getCandidates().size() == 4'194'304);
    CHECK(zreduction.getIndex() == 7);
    CHECK(contains(zreduction.getCandidates(), z7 & mask<2, 32>));
}

TEST("reduce completely and generate")
{
    const auto keystream = makeKeystream(12);
    const auto z7        = getZvalue(7);
    const auto z11       = getZvalue(11);

    auto zreduction = Zreduction{keystream};
    CHECK(zreduction.getCandidates().size() == 2'686'976);
    CHECK(zreduction.getIndex() == 11);
    CHECK(contains(zreduction.getCandidates(), z11 & mask<10, 32>));

    auto os       = std::ostringstream{};
    auto progress = Progress{os};
    zreduction.reduce(progress);
    CHECK(progress.done == 4);
    CHECK(progress.total == 4);
    CHECK(progress.state == Progress::State::Normal);
    CHECK(os.str().empty());
    CHECK(zreduction.getCandidates().size() == 898'165);
    CHECK(zreduction.getIndex() == 7);
    CHECK(contains(zreduction.getCandidates(), z7 & mask<10, 32>));

    zreduction.generate();
    CHECK(zreduction.getCandidates().size() == 1'368'208);
    CHECK(zreduction.getIndex() == 7);
    CHECK(contains(zreduction.getCandidates(), z7 & mask<2, 32>));
}

TEST("reduce partially and generate")
{
    const auto keystream = makeKeystream(14'336);
    const auto z9999     = getZvalue(9999);
    const auto z14335    = getZvalue(14335);

    auto zreduction = Zreduction{keystream};
    CHECK(zreduction.getCandidates().size() == 2'686'976);
    CHECK(zreduction.getIndex() == 14335);
    CHECK(contains(zreduction.getCandidates(), z14335 & mask<10, 32>));

    auto os       = std::ostringstream{};
    auto progress = Progress{os};
    zreduction.reduce(progress);
    CHECK(progress.done == 5207);
    CHECK(progress.total == 14328);
    CHECK(progress.state == Progress::State::EarlyExit);
    CHECK(os.str().empty());
    CHECK(zreduction.getCandidates().size() == 153);
    CHECK(zreduction.getIndex() == 9999);
    CHECK(contains(zreduction.getCandidates(), z9999 & mask<10, 32>));

    zreduction.generate();
    CHECK(zreduction.getCandidates().size() == 218);
    CHECK(zreduction.getIndex() == 9999);
    CHECK(contains(zreduction.getCandidates(), z9999 & mask<2, 32>));
}
