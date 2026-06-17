#include <bkcrack/Attack.hpp>

#include <TestRunner.hpp>

#include <sstream>

namespace
{
const auto plaintext = std::vector<std::uint8_t>{
    'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!',
};
const auto ciphertext = std::vector<std::uint8_t>{
    0x3e, 0xb4, 0xc5, 0x92, 0x58, 0x40, 0x9a, 0x6c, 0xed, 0x99, 0x65, 0x81,
    0x66, 0x1b, 0x1d, 0xda, 0x5d, 0x8a, 0x8c, 0x30, 0x07, 0x76, 0x50, 0xbb,
};

const auto z7      = 0x74930e66;
const auto z7_2_32 = std::vector<std::uint32_t>{
    0x00000000, 0x10000000, 0x20000000, 0x30000000, 0x40000000, 0x50000000, 0x60000000, z7& mask<2, 32>,
    0x80000000, 0x90000000, 0xa0000000, 0xb0000000, 0xc0000000, 0xd0000000, 0xe0000000, 0xf0000000,
};

const auto z9      = 0x69196cee;
const auto z9_2_32 = std::vector<std::uint32_t>{
    0x00000000, 0x10000000, 0x20000000, 0x30000000, 0x40000000, 0x50000000, z9& mask<2, 32>, 0x70000000,
    0x80000000, 0x90000000, 0xa0000000, 0xb0000000, 0xc0000000, 0xd0000000, 0xe0000000,      0xf0000000,
};
} // namespace

TEST("simple case")
{
    const auto data     = Data{ciphertext, {}, plaintext, 0, {}};
    auto       start    = 0;
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};

    const auto result = attack(data, z7_2_32, start, 7, 1, false, progress);

    CHECK(result.size() == 1);
    CHECK(result[0].getX() == 0xea9b4e4d);
    CHECK(result[0].getY() == 0xba789085);
    CHECK(result[0].getZ() == 0x5ff8707d);

    CHECK(start == 8);
    CHECK(progress.done == 8);
    CHECK(progress.total == 16);
    CHECK(progress.state == Progress::State::EarlyExit);
}

TEST("offset and extra plaintext")
{
    const auto plaintext2 = std::vector<std::uint8_t>{plaintext.begin() + 2, plaintext.end() - 2};
    const auto extra      = std::map<int, std::uint8_t>{{-2, 0x65 ^ 0x7d}, {-1, 0x81 ^ 0x0d}, {0, 'H'}, {11, '!'}};
    const auto data       = Data{ciphertext, {}, plaintext2, 2, extra};
    auto       start      = 0;
    auto       os         = std::ostringstream{};
    auto       progress   = Progress{os};

    const auto result = attack(data, z9_2_32, start, 7, 1, false, progress);

    CHECK(result.size() == 1);
    CHECK(result[0].getX() == 0xea9b4e4d);
    CHECK(result[0].getY() == 0xba789085);
    CHECK(result[0].getZ() == 0x5ff8707d);

    CHECK(start == 7);
    CHECK(progress.done == 7);
    CHECK(progress.total == 16);
    CHECK(progress.state == Progress::State::EarlyExit);
}

TEST("restart point before solution")
{
    const auto data     = Data{ciphertext, {}, plaintext, 0, {}};
    auto       start    = 4;
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};

    const auto result = attack(data, z7_2_32, start, 7, 1, false, progress);

    CHECK(result.size() == 1);
    CHECK(result[0].getX() == 0xea9b4e4d);
    CHECK(result[0].getY() == 0xba789085);
    CHECK(result[0].getZ() == 0x5ff8707d);

    CHECK(start == 8);
    CHECK(progress.done == 8);
    CHECK(progress.total == 16);
    CHECK(progress.state == Progress::State::EarlyExit);
}

TEST("restart point past solution")
{
    const auto data     = Data{ciphertext, {}, plaintext, 0, {}};
    auto       start    = 8;
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};

    const auto result = attack(data, z7_2_32, start, 7, 1, false, progress);

    CHECK(result.empty());

    CHECK(start == 16);
    CHECK(progress.done == 16);
    CHECK(progress.total == 16);
    CHECK(progress.state == Progress::State::Normal);
}

TEST("exhaustive attack")
{
    const auto data     = Data{ciphertext, {}, plaintext, 0, {}};
    auto       start    = 0;
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};

    const auto result = attack(data, z7_2_32, start, 7, 1, true, progress);

    CHECK(result.size() == 1);
    CHECK(result[0].getX() == 0xea9b4e4d);
    CHECK(result[0].getY() == 0xba789085);
    CHECK(result[0].getZ() == 0x5ff8707d);

    CHECK(start == 16);
    CHECK(progress.done == 16);
    CHECK(progress.total == 16);
    CHECK(progress.state == Progress::State::Normal);
}
