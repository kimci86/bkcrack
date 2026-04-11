#ifndef BKCRACK_TESTRUNNER_HPP
#define BKCRACK_TESTRUNNER_HPP

#include <exception>
#include <source_location>
#include <string>

struct TestError
{
    std::string          expression;
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
                throw TestError{std::string{#__VA_ARGS__ " should throw " #ErrorType " with message \"" message        \
                                                         "\", got message \""} +                                       \
                                error.what() + "\""};                                                                  \
        }                                                                                                              \
        catch (const std::exception& error)                                                                            \
        {                                                                                                              \
            throw TestError{std::string{#__VA_ARGS__ " should throw " #ErrorType                                       \
                                                     ", a different exception occurred with message \""} +             \
                            error.what() + "\""};                                                                      \
        }                                                                                                              \
        catch (...)                                                                                                    \
        {                                                                                                              \
            throw TestError{#__VA_ARGS__ " should throw " #ErrorType ", a different exception occurred"};              \
        }                                                                                                              \
        throw TestError{#__VA_ARGS__ " should throw " #ErrorType ", no exception occurred"};                           \
    } while (false)

struct TestRegistration
{
    TestRegistration(const char* name, void (&function)(), std::source_location location);
};

#define CONCAT_IMPL(prefix, line) prefix##line
#define CONCAT(prefix, line) CONCAT_IMPL(prefix, line)
#define IDENTIFIER_WITH_LINE(prefix) CONCAT(prefix, __LINE__)

#define TEST(name)                                                                                                     \
    void IDENTIFIER_WITH_LINE(testFunction)();                                                                         \
    namespace                                                                                                          \
    {                                                                                                                  \
    const auto IDENTIFIER_WITH_LINE(testRegistration) = TestRegistration{name, IDENTIFIER_WITH_LINE(testFunction),     \
                                                                         std::source_location::current()};             \
    }                                                                                                                  \
    void IDENTIFIER_WITH_LINE(testFunction)()

struct TestRunner
{
    static auto runAllTests() -> bool;
};

#endif // BKCRACK_TESTRUNNER_HPP
