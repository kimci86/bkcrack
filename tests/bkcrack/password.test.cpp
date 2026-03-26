#include <bkcrack/password.hpp>

#include <TestRunner.hpp>

#include <algorithm>
#include <numeric>
#include <sstream>

namespace
{
auto makeCharset(std::uint8_t front, std::uint8_t back)
{
    auto vector = std::vector<std::uint8_t>(back - front + 1);
    std::iota(vector.begin(), vector.end(), front);
    return vector;
}
auto charsetUnion(const std::vector<std::uint8_t>& charsetA, const std::vector<std::uint8_t>& charsetB)
{
    auto vector = std::vector<std::uint8_t>{};
    std::ranges::merge(charsetA, charsetB, std::back_inserter(vector));
    return vector;
}
auto charsetDifference(const std::vector<std::uint8_t>& charsetA, const std::vector<std::uint8_t>& charsetB)
{
    auto vector = std::vector<std::uint8_t>{};
    for (const auto c : charsetA)
        if (!std::ranges::binary_search(charsetB, c))
            vector.push_back(c);
    return vector;
}
const auto b  = makeCharset(0, 255);
const auto p  = makeCharset(' ', '~');
const auto d  = makeCharset('0', '9');
const auto u  = makeCharset('A', 'Z');
const auto l  = makeCharset('a', 'z');
const auto a  = charsetUnion(charsetUnion(l, u), d);
const auto s  = charsetDifference(p, a);
const auto sl = charsetUnion(s, l);
} // namespace

TEST("bruteforce empty password")
{
    auto       start    = std::string{};
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};
    const auto result   = recoverPassword(Keys{}, l, 0, 8, start, 1, false, progress);

    CHECK(result.size() == 1);
    CHECK(result[0] == "");

    CHECK(start == "");
    CHECK(progress.done == 0);
    CHECK(progress.total == 0);
    CHECK(progress.state == Progress::State::EarlyExit);
}

TEST("bruteforce password of 4 bytes")
{
    auto       start    = std::string{};
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};
    const auto result   = recoverPassword({0x1b226dfe, 0xc089e0a3, 0x6af00ee6}, b, 0, 4, start, 1, false, progress);

    CHECK(result.size() == 1);
    CHECK(result[0] == "🔐");

    CHECK(start == "");
    CHECK(progress.done == 0);
    CHECK(progress.total == 0);
    CHECK(progress.state == Progress::State::EarlyExit);
}

TEST("bruteforce password of 8 characters")
{
    auto       start    = std::string{};
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};
    const auto result   = recoverPassword({0x9bcb20c6, 0x10a97ca5, 0x103c0614}, p, 0, 8, start, 1, false, progress);

    CHECK(result.size() == 1);
    CHECK(result[0] == "_S#cr3t!");

    CHECK(start == "");
    CHECK(progress.done == 0);
    CHECK(progress.total == 0);
    CHECK(progress.state == Progress::State::EarlyExit);
}

TEST("bruteforce password of 10 characters")
{
    auto       start    = std::string{};
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};
    const auto result   = recoverPassword({0xedb43a00, 0x9ce6e179, 0x8cf2cbba}, a, 0, 10, start, 1, false, progress);

    CHECK(result.size() == 1);
    CHECK(result[0] == "q1w2e3r4t5");

    CHECK(start == "r000");
    CHECK(progress.done == 53 * 62 + 0);
    CHECK(progress.total == 62 * 62);
    CHECK(progress.state == Progress::State::EarlyExit);
}

TEST("bruteforce password of 12 characters")
{
    auto       start    = std::string{};
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};
    const auto result   = recoverPassword({0xdcce7593, 0xb8a2e617, 0xb2bd4365}, l, 0, 12, start, 1, false, progress);

    CHECK(result.size() == 1);
    CHECK(result[0] == "abcdefghijkl");

    CHECK(start == "abdaaa");
    CHECK(progress.done == 0 * 26 + 1);
    CHECK(progress.total == 26 * 26);
    CHECK(progress.state == Progress::State::EarlyExit);
}

TEST("bruteforce password of 14 characters with restart point")
{
    auto       start    = std::string{"mmzzzaaa"};
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};
    const auto result   = recoverPassword({0x1272ef9e, 0x20884732, 0x7a39ab85}, l, 0, 14, start, 1, false, progress);

    CHECK(result.size() == 1);
    CHECK(result[0] == "mnbzzghijklmno");

    CHECK(start == "mncaaaaa");
    CHECK(progress.done == 12 * 26 + 13);
    CHECK(progress.total == 26 * 26);
    CHECK(progress.state == Progress::State::EarlyExit);
}

TEST("exhaustive bruteforce")
{
    auto       start    = std::string{};
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};
    const auto result   = recoverPassword({0xedb43a00, 0x9ce6e179, 0x8cf2cbba}, a, 0, 10, start, 1, true, progress);

    CHECK(result.size() == 1);
    CHECK(result[0] == "q1w2e3r4t5");

    CHECK(start == "");
    CHECK(progress.done == 62 * 62);
    CHECK(progress.total == 62 * 62);
    CHECK(progress.state == Progress::State::Normal);
}

TEST("bruteforce attempt with solution out of given charset")
{
    auto       start    = std::string{};
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};
    const auto result   = recoverPassword({0xf1f9ab49, 0x8574a6fd, 0xcb99758d}, d, 0, 6, start, 1, false, progress);

    CHECK(result.empty());

    CHECK(start == "");
    CHECK(progress.done == 0);
    CHECK(progress.total == 0);
    CHECK(progress.state == Progress::State::Normal);
    CHECK(os.str().find("Password: 123x56 (as bytes: 31 32 33 78 35 36)") != std::string::npos);
}

TEST("mask-based recovery on empty password")
{
    auto       start    = std::string{};
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};
    const auto result   = recoverPassword(Keys{}, {}, start, 1, false, progress);

    CHECK(result.size() == 1);
    CHECK(result[0] == "");

    CHECK(start == "");
    CHECK(progress.done == 0);
    CHECK(progress.total == 0);
    CHECK(progress.state == Progress::State::EarlyExit);
}

TEST("mask-based recovery on password of 5 characters")
{
    auto       start    = std::string{};
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};
    const auto result =
        recoverPassword({0x5e07e483, 0x0c4900a4, 0x4e586ac1}, {u, l, d, s, {'.'}}, start, 1, false, progress);

    CHECK(result.size() == 1);
    CHECK(result[0] == "Aa1_.");

    CHECK(start == "");
    CHECK(progress.done == 0);
    CHECK(progress.total == 0);
    CHECK(progress.state == Progress::State::EarlyExit);
}

TEST("mask-based recovery on password of 6 characters")
{
    auto       start    = std::string{};
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};
    const auto result =
        recoverPassword({0xf9720e40, 0x2520f2b9, 0x0a5660df}, {d, l, d, l, d, l}, start, 1, false, progress);

    CHECK(result.size() == 1);
    CHECK(result[0] == "1q2w3e");

    CHECK(start == "");
    CHECK(progress.done == 0);
    CHECK(progress.total == 0);
    CHECK(progress.state == Progress::State::EarlyExit);
}

TEST("mask-based recovery on password of 7 characters")
{
    auto       start    = std::string{};
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};
    const auto result =
        recoverPassword({0x2af9b027, 0x85bd8154, 0x286ca64f}, {l, l, l, l, l, l, l}, start, 1, false, progress);

    CHECK(result.size() == 1);
    CHECK(result[0] == "letmein");

    CHECK(start == "");
    CHECK(progress.done == 0);
    CHECK(progress.total == 0);
    CHECK(progress.state == Progress::State::EarlyExit);
}

TEST("mask-based recovery on password of 13 characters")
{
    auto       start    = std::string{};
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};
    const auto result   = recoverPassword({0x0d892b8b, 0x02dd8fad, 0x77f52c7b},
                                          {l, l, l, l, l, l, l, l, {'-'}, d, d, d, d}, start, 1, false, progress);

    CHECK(result.size() == 1);
    CHECK(result[0] == "password-1234");

    CHECK(start == "4400-aa");
    CHECK(progress.done == 44);
    CHECK(progress.total == 100);
    CHECK(progress.state == Progress::State::EarlyExit);
}

TEST("mask-based recovery with restart point")
{
    auto       start    = std::string{"4200-aa"};
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};
    const auto result   = recoverPassword({0x0d892b8b, 0x02dd8fad, 0x77f52c7b},
                                          {l, l, l, l, l, l, l, l, {'-'}, d, d, d, d}, start, 1, false, progress);

    CHECK(result.size() == 1);
    CHECK(result[0] == "password-1234");

    CHECK(start == "4400-aa");
    CHECK(progress.done == 44);
    CHECK(progress.total == 100);
    CHECK(progress.state == Progress::State::EarlyExit);
}

TEST("exhaustive mask-based recovery")
{
    auto       start    = std::string{};
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};
    const auto result   = recoverPassword({0x0d892b8b, 0x02dd8fad, 0x77f52c7b},
                                          {l, l, l, l, l, l, l, l, {'-'}, d, d, d, d}, start, 1, true, progress);

    CHECK(result.size() == 1);
    CHECK(result[0] == "password-1234");

    CHECK(start == "");
    CHECK(progress.done == 100);
    CHECK(progress.total == 100);
    CHECK(progress.state == Progress::State::Normal);
}

TEST("mask-based recovery attempt with solution out of given mask")
{
    auto       start    = std::string{};
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};
    const auto result   = recoverPassword({0x6cf4e702, 0x193a82f5, 0x88360a9f},
                                          {l, l, l, l, l, l, l, l, {'-'}, d, d, d, d}, start, 1, false, progress);

    CHECK(result.empty());

    CHECK(start == "");
    CHECK(progress.done == 100);
    CHECK(progress.total == 100);
    CHECK(progress.state == Progress::State::Normal);
    const auto s = os.str();
    CHECK(os.str().find("Password: passw*rd-1234 (as bytes: 70 61 73 73 77 2a 72 64 2d 31 32 33 34)") !=
          std::string::npos);
}

TEST("mask-based recovery with constant mask")
{
    auto       start    = std::string{};
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};
    const auto result =
        recoverPassword({0xc80f5189, 0xce16bd43, 0x38247eb5},
                        {{'L'}, {'o'}, {'r'}, {'e'}, {'m'}, {' '}, {'i'}, {'p'}, {'s'}, {'u'}, {'m'}, {' '}, {'d'},
                         {'o'}, {'l'}, {'o'}, {'r'}, {' '}, {'s'}, {'i'}, {'t'}, {' '}, {'a'}, {'m'}, {'e'}, {'t'}},
                        start, 1, false, progress);

    CHECK(result.size() == 1);
    CHECK(result[0] == "Lorem ipsum dolor sit amet");

    CHECK(start == "");
    CHECK(progress.done == 0);
    CHECK(progress.total == 0);
    CHECK(progress.state == Progress::State::EarlyExit);
}

TEST("mask-based recovery with constant prefix")
{
    auto       start    = std::string{};
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};
    const auto result =
        recoverPassword({0xc80f5189, 0xce16bd43, 0x38247eb5},
                        {{'L'}, {'o'}, {'r'}, {'e'}, {'m'}, {' '}, {'i'}, {'p'}, {'s'}, {'u'}, {'m'}, {' '}, {'d'},
                         {'o'}, {'l'}, {'o'}, {'r'}, {' '}, sl,    sl,    sl,    sl,    sl,    sl,    sl,    sl},
                        start, 1, false, progress);

    CHECK(result.size() == 1);
    CHECK(result[0] == "Lorem ipsum dolor sit amet");

    CHECK(start == "");
    CHECK(progress.done == 0);
    CHECK(progress.total == 0);
    CHECK(progress.state == Progress::State::EarlyExit);
}

TEST("mask-based recovery with constant suffix")
{
    auto       start    = std::string{};
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};
    const auto result =
        recoverPassword({0xc80f5189, 0xce16bd43, 0x38247eb5},
                        {u,     sl,    sl,    sl,    sl,    {' '}, {'i'}, {'p'}, {'s'}, {'u'}, {'m'}, {' '}, {'d'},
                         {'o'}, {'l'}, {'o'}, {'r'}, {' '}, {'s'}, {'i'}, {'t'}, {' '}, {'a'}, {'m'}, {'e'}, {'t'}},
                        start, 1, false, progress);

    CHECK(result.size() == 1);
    CHECK(result[0] == "Lorem ipsum dolor sit amet");

    CHECK(start == "");
    CHECK(progress.done == 0);
    CHECK(progress.total == 0);
    CHECK(progress.state == Progress::State::EarlyExit);
}

TEST("mask-based recovery with constant prefix and suffix")
{

    auto       start    = std::string{};
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};
    const auto result =
        recoverPassword({0xc80f5189, 0xce16bd43, 0x38247eb5},
                        {{'L'}, {'o'}, {'r'}, {'e'}, {'m'}, {' '}, {'i'}, {'p'}, {'s'}, {'u'}, {'m'}, {' '}, sl,
                         sl,    sl,    sl,    sl,    sl,    sl,    sl,    sl,    {' '}, {'a'}, {'m'}, {'e'}, {'t'}},
                        start, 1, false, progress);

    CHECK(result.size() == 1);
    CHECK(result[0] == "Lorem ipsum dolor sit amet");

    CHECK(start == "");
    CHECK(progress.done == 0);
    CHECK(progress.total == 0);
    CHECK(progress.state == Progress::State::EarlyExit);
}

TEST("mask-based recovery with sparse constant characters")
{

    auto       start    = std::string{};
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};
    const auto result =
        recoverPassword({0xc80f5189, 0xce16bd43, 0x38247eb5},
                        {{'L'}, {'o'}, l,     {'e'}, l,     {' '}, {'i'}, l,     {'s'}, l,     {'m'}, {' '}, {'d'},
                         {'o'}, l,     {'o'}, l,     {' '}, {'s'}, {'i'}, {'t'}, {' '}, {'a'}, l,     {'e'}, {'t'}},
                        start, 1, false, progress);

    CHECK(result.size() == 1);
    CHECK(result[0] == "Lorem ipsum dolor sit amet");

    CHECK(start == "tena tis aoaod Loaea");
    CHECK(progress.done == 0);
    CHECK(progress.total == 0);
    CHECK(progress.state == Progress::State::EarlyExit);
}
