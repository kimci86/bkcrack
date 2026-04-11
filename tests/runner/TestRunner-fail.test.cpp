#include <TestRunner.hpp>

#include <stdexcept>

TEST("failed check")
{
    CHECK(1 + 1 != 2);
}

TEST("missing exception")
{
    const auto notThrowing = [] {};
    CHECK_THROWS(std::runtime_error, "", notThrowing());
}

TEST("mismatching exception type")
{
    const auto throwing = [] { throw 42; };
    CHECK_THROWS(std::runtime_error, "", throwing());
}

TEST("mismatching std::exception type")
{
    const auto throwing = [] { throw std::invalid_argument{"invalid argument"}; };
    CHECK_THROWS(std::runtime_error, "", throwing());
}

TEST("mismatching exception message")
{
    const auto throwing = [] { throw std::invalid_argument{"invalid argument"}; };
    CHECK_THROWS(std::invalid_argument, "error", throwing());
}

TEST("throw exception")
{
    throw std::runtime_error{"runtime error"};
}

TEST("throw something else")
{
    throw 42;
}
