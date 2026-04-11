#include "TestRunner.hpp"

#include <chrono>
#include <iostream>
#include <string_view>
#include <vector>

namespace
{

struct TestCase
{
    const char* name;
    void (&function)();
    std::source_location location;
};

auto testRegistry() -> std::vector<TestCase>&
{
    static auto tests = std::vector<TestCase>{};
    return tests;
}

} // namespace

auto checkMessageContains(const char* actual, const char* expected) -> bool
{
    return std::string_view{actual}.find(expected) != std::string_view::npos;
}

TestRegistration::TestRegistration(const char* name, void (&function)(), std::source_location location)
{
    testRegistry().emplace_back(name, function, location);
}

auto TestRunner::runAllTests() -> bool
{
    auto pass = 0;
    auto fail = 0;

    const auto allStart = std::chrono::high_resolution_clock::now();
    for (const auto& [name, function, location] : testRegistry())
    {
        std::cout << name << std::flush;

        const auto maybeDuration = [start = std::chrono::high_resolution_clock::now()]()
        {
            const auto end = std::chrono::high_resolution_clock::now();
            if (const auto duration = end - start; duration > std::chrono::milliseconds{1})
            {
                auto oss = std::ostringstream{};
                oss << " (" << std::chrono::duration_cast<std::chrono::milliseconds>(duration).count() << " ms)";
                return std::move(oss).str();
            }
            return std::string{};
        };

        try
        {
            function();
            std::cout << " [PASS]" << maybeDuration() << std::endl;
            ++pass;
        }
        catch (const TestError& error)
        {
            std::cout << " [FAIL]" << maybeDuration();
            std::cout << "\n  " << error.location.file_name() << ':' << error.location.line() //
                      << "\n  " << error.expression << std::endl;
            ++fail;
        }
        catch (const std::exception& error)
        {
            std::cout << " [FAIL]" << maybeDuration();
            std::cout << "\n  " << location.file_name() << ':' << location.line() //
                      << "\n  an exception occurred with message \"" << error.what() << "\"" << std::endl;
            ++fail;
        }
        catch (...)
        {
            std::cout << " [FAIL]" << maybeDuration();
            std::cout << "\n  " << location.file_name() << ':' << location.line() //
                      << "\n  an exception occurred" << std::endl;
            ++fail;
        }
    }

    std::cout << "Tests: " << pass << " pass, " << fail << " fail";
    const auto allEnd = std::chrono::high_resolution_clock::now();
    if (const auto duration = allEnd - allStart; duration > std::chrono::milliseconds{1})
        std::cout << " (" << std::chrono::duration_cast<std::chrono::milliseconds>(duration).count() << " ms)";
    std::cout << std::endl;

    return !fail;
}
