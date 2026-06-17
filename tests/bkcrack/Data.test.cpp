#include <bkcrack/Data.hpp>
#include <bkcrack/Keys.hpp>

#include <TestRunner.hpp>

#include <string_view>

namespace
{
const auto plaintext = std::vector<std::uint8_t>{
    'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!',
};
const auto ciphertext = std::vector<std::uint8_t>{
    0x3e, 0xb4, 0xc5, 0x92, 0x58, 0x40, 0x9a, 0x6c, 0xed, 0x99, 0x65, 0x81,
    0x66, 0x1b, 0x1d, 0xda, 0x5d, 0x8a, 0x8c, 0x30, 0x07, 0x76, 0x50, 0xbb,
};
const auto keystream = std::vector<std::uint8_t>{
    0xee, 0x96, 0x22, 0x47, 0x78, 0xb8, 0x73, 0x54, 0x4c, 0xd7, 0x7d, 0x0d,
    0x2e, 0x7e, 0x71, 0xb6, 0x32, 0xaa, 0xdb, 0x5f, 0x75, 0x1a, 0x34, 0x9a,
};

auto prefix(const std::vector<std::uint8_t>& vector, std::size_t length) -> std::vector<std::uint8_t>
{
    return std::vector<std::uint8_t>{vector.begin(), vector.begin() + length};
}
auto slice(const std::vector<std::uint8_t>& vector, std::size_t begin, std::size_t end) -> std::vector<std::uint8_t>
{
    return std::vector<std::uint8_t>{vector.begin() + begin, vector.begin() + end};
}
} // namespace

TEST("Data::Error")
{
    const auto error = Data::Error{"description"};
    CHECK(error.what() == std::string_view{"Data error: description."});
}

TEST("contiguous plaintext only")
{
    const auto data = Data{ciphertext, {}, plaintext, 0, {}};
    CHECK(data.ciphertext == ciphertext);
    CHECK(data.plaintext == plaintext);
    CHECK(data.offset == 12);
    CHECK(data.keystream == slice(keystream, 12, 24));
    CHECK(data.extraPlaintext.empty());
}

TEST("contiguous plaintext and sparse extra plaintext")
{
    const auto data = Data{ciphertext, {}, prefix(plaintext, 8), 0, {{-3, 0x4e}, {-2, 0x18}, {10, 'd'}, {11, '!'}}};
    CHECK(data.ciphertext == ciphertext);
    CHECK(data.plaintext == prefix(plaintext, 8));
    CHECK(data.offset == 12);
    CHECK(data.keystream == slice(keystream, 12, 20));
    CHECK(data.extraPlaintext == decltype(data.extraPlaintext){{22, 'd'}, {23, '!'}, {10, 0x18}, {9, 0x4e}});
}

TEST("merge extra plaintext after")
{
    const auto data = Data{ciphertext, {}, prefix(plaintext, 10), 0, {{10, 'd'}, {11, '!'}}};
    CHECK(data.ciphertext == ciphertext);
    CHECK(data.plaintext == plaintext);
    CHECK(data.offset == 12);
    CHECK(data.keystream == slice(keystream, 12, 24));
    CHECK(data.extraPlaintext.empty());
}

TEST("merge extra plaintext before")
{
    const auto data = Data{ciphertext, {}, slice(plaintext, 2, 12), 2, {{0, 'H'}, {1, 'e'}}};
    CHECK(data.ciphertext == ciphertext);
    CHECK(data.plaintext == plaintext);
    CHECK(data.offset == 12);
    CHECK(data.keystream == slice(keystream, 12, 24));
    CHECK(data.extraPlaintext.empty());
}

TEST("overwrite contiguous plaintext with extra plaintext")
{
    auto overwrittenPlaintext = plaintext;
    overwrittenPlaintext[5]   = '*';

    auto overwrittenKeystream = keystream;
    overwrittenKeystream[17]  = ciphertext[17] ^ '*';

    const auto data = Data{ciphertext, {}, plaintext, 0, {{5, '*'}}};
    CHECK(data.ciphertext == ciphertext);
    CHECK(data.plaintext == overwrittenPlaintext);
    CHECK(data.offset == 12);
    CHECK(data.keystream == slice(overwrittenKeystream, 12, 24));
    CHECK(data.extraPlaintext.empty());
}

TEST("long contiguous extra plaintext after")
{
    const auto data = Data{ciphertext,
                           {},
                           {0x8c, 'H', 'e', 'l'},
                           -1,
                           {{4, 'o'}, {5, ' '}, {6, 'W'}, {7, 'o'}, {8, 'r'}, {9, 'l'}, {10, 'd'}, {11, '!'}}};
    CHECK(data.ciphertext == ciphertext);
    CHECK(data.plaintext == slice(plaintext, 4, 12));
    CHECK(data.offset == 16);
    CHECK(data.keystream == slice(keystream, 16, 24));
    CHECK(data.extraPlaintext == decltype(data.extraPlaintext){{14, 'l'}, {13, 'e'}, {12, 'H'}, {11, 0x8c}});
}

TEST("long contiguous extra plaintext before")
{
    const auto data = Data{ciphertext,
                           {},
                           {'r', 'l', 'd', '!'},
                           8,
                           {{-1, 0x8c}, {0, 'H'}, {1, 'e'}, {2, 'l'}, {3, 'l'}, {4, 'o'}, {5, ' '}, {6, 'W'}}};
    CHECK(data.ciphertext == ciphertext);
    CHECK(data.plaintext == decltype(data.plaintext){0x8c, 'H', 'e', 'l', 'l', 'o', ' ', 'W'});
    CHECK(data.offset == 11);
    CHECK(data.keystream == slice(keystream, 11, 19));
    CHECK(data.extraPlaintext == decltype(data.extraPlaintext){{20, 'r'}, {21, 'l'}, {22, 'd'}, {23, '!'}});
}

TEST("extra plaintext only")
{
    const auto extraPlaintext = std::map<int, std::uint8_t>{
        {0, 'H'}, {1, 'e'}, {2, 'l'}, {3, 'l'}, {4, 'o'},  {5, ' '},
        {6, 'W'}, {7, 'o'}, {8, 'r'}, {9, 'l'}, {10, 'd'}, {11, '!'},
    };
    const auto data = Data{ciphertext, {}, {}, -1, extraPlaintext};
    CHECK(data.ciphertext == ciphertext);
    CHECK(data.plaintext == plaintext);
    CHECK(data.offset == 12);
    CHECK(data.keystream == slice(keystream, 12, 24));
    CHECK(data.extraPlaintext.empty());
}

TEST("check byte added to plaintext")
{
    const auto data = Data{ciphertext, 0x8c, plaintext, 0, {}};
    CHECK(data.ciphertext == ciphertext);
    CHECK(data.plaintext == decltype(data.plaintext){0x8c, 'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'});
    CHECK(data.offset == 11);
    CHECK(data.keystream == slice(keystream, 11, 24));
    CHECK(data.extraPlaintext.empty());
}

TEST("check byte added to extra plaintext")
{
    const auto data = Data{ciphertext, 0x8c, slice(plaintext, 2, 10), 2, {{-3, 0x4e}, {-2, 0x18}, {11, '!'}}};
    CHECK(data.ciphertext == ciphertext);
    CHECK(data.plaintext == slice(plaintext, 2, 10));
    CHECK(data.offset == 14);
    CHECK(data.keystream == slice(keystream, 14, 22));
    CHECK(data.extraPlaintext == decltype(data.extraPlaintext){{23, '!'}, {11, 0x8c}, {10, 0x18}, {9, 0x4e}});
}

TEST("check byte overridden by plaintext")
{
    const auto data =
        Data{ciphertext, 0xff, {0x8c, 'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'}, -1, {}};
    CHECK(data.ciphertext == ciphertext);
    CHECK(data.plaintext == decltype(data.plaintext){0x8c, 'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'});
    CHECK(data.offset == 11);
    CHECK(data.keystream == slice(keystream, 11, 24));
    CHECK(data.extraPlaintext.empty());
}

TEST("check byte overridden by extra plaintext")
{
    const auto data = Data{ciphertext, 0x8c, slice(plaintext, 2, 12), 2, {{-2, 0x18}, {-1, 0xff}}};
    CHECK(data.ciphertext == ciphertext);
    CHECK(data.plaintext == slice(plaintext, 2, 12));
    CHECK(data.offset == 14);
    CHECK(data.keystream == slice(keystream, 14, 24));
    CHECK(data.extraPlaintext == decltype(data.extraPlaintext){{11, 0xff}, {10, 0x18}});
}

TEST("not enough data")
{
    CHECK_THROWS(Data::Error, "ciphertext is too small for an attack (minimum length is 12)",
                 Data{prefix(ciphertext, 11), {}, prefix(plaintext, 11), -12, {}});

    CHECK_THROWS(Data::Error, "ciphertext is smaller than plaintext",
                 Data{prefix(ciphertext, 12), {}, std::vector<std::uint8_t>('A', 13), -12, {}});

    CHECK_THROWS(Data::Error, "not enough contiguous plaintext (7 bytes available, minimum is 8)",
                 Data{ciphertext, {}, prefix(plaintext, 7), 0, {}});

    CHECK_THROWS(Data::Error, "not enough plaintext (11 bytes available, minimum is 12)",
                 Data{ciphertext, {}, prefix(plaintext, 9), 0, {{10, 'd'}, {11, '!'}}});
}

TEST("invalid offset")
{
    CHECK_THROWS(Data::Error, "plaintext offset -13 is too small (minimum is -12)",
                 Data{ciphertext, {}, plaintext, -13, {}});

    CHECK_THROWS(Data::Error, "plaintext offset 1 is too large", Data{ciphertext, {}, plaintext, 1, {}});

    CHECK_THROWS(Data::Error, "extra plaintext offset -13 is too small (minimum is -12)",
                 Data{ciphertext, {}, plaintext, 0, {{-13, 0x00}}});

    CHECK_THROWS(Data::Error, "extra plaintext offset 12 is too large",
                 Data{ciphertext, {}, plaintext, 0, {{12, 0x00}}});
}
