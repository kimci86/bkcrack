#ifndef BKCRACK_TESTRUNNER_HPP
#define BKCRACK_TESTRUNNER_HPP

#include <source_location>

struct TestError
{
    const char*          expression;
    std::source_location location = std::source_location::current();
};

#define CHECK(...)                                                                                                     \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(__VA_ARGS__))                                                                                            \
            throw TestError{#__VA_ARGS__};                                                                             \
    } while (false)

auto checkMessageContains(const char* actual, const char* expected) -> bool;

#define CHECK_THROWS(ErrorType, message, ...)                                                                          \
    do                                                                                                                 \
    {                                                                                                                  \
        try                                                                                                            \
        {                                                                                                              \
            (void)__VA_ARGS__;                                                                                         \
        }                                                                                                              \
        catch (const ErrorType& error)                                                                                 \
        {                                                                                                              \
            if (checkMessageContains(error.what(), message))                                                           \
                break;                                                                                                 \
            else                                                                                                       \
                throw TestError{#__VA_ARGS__ " should throw " #ErrorType " with message \"" message "\""};             \
        }                                                                                                              \
        throw TestError{#__VA_ARGS__ " should throw " #ErrorType};                                                     \
    } while (false)

struct TestRegistration
{
    TestRegistration(const char* name, void (&function)());
};

#define CONCAT_IMPL(prefix, line) prefix##line
#define CONCAT(prefix, line) CONCAT_IMPL(prefix, line)
#define IDENTIFIER_WITH_LINE(prefix) CONCAT(prefix, __LINE__)

#define TEST(name)                                                                                                     \
    void IDENTIFIER_WITH_LINE(testFunction)();                                                                         \
    namespace                                                                                                          \
    {                                                                                                                  \
    const auto IDENTIFIER_WITH_LINE(testRegistration) = TestRegistration{name, IDENTIFIER_WITH_LINE(testFunction)};    \
    }                                                                                                                  \
    void IDENTIFIER_WITH_LINE(testFunction)()

struct TestRunner
{
    static auto runAllTests() -> bool;
};

#endif // BKCRACK_TESTRUNNER_HPP
