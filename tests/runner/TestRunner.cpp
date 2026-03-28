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

TestRegistration::TestRegistration(const char* name, void (&function)())
{
    testRegistry().emplace_back(name, function);
}

auto TestRunner::runAllTests() -> bool
{
    auto pass = 0;
    auto fail = 0;

    const auto allStart = std::chrono::high_resolution_clock::now();
    for (const auto& [name, function] : testRegistry())
    {
        std::cout << name << std::flush;
        const auto start = std::chrono::high_resolution_clock::now();
        try
        {
            function();
            std::cout << " [PASS]";
            ++pass;
        }
        catch (const TestError& error)
        {
            std::cout << "\n  " << error.location.file_name() << ':' << error.location.line() //
                      << "\n  " << error.expression << " [FAIL]";
            ++fail;
        }
        catch (const std::exception& error)
        {
            std::cout << "\n  " << error.what() << " [FAIL]";
            ++fail;
        }
        catch (...)
        {
            std::cout << "\n  exception [FAIL]";
            ++fail;
        }
        const auto end = std::chrono::high_resolution_clock::now();
        if (const auto duration = end - start; duration > std::chrono::milliseconds{1})
            std::cout << " (" << std::chrono::duration_cast<std::chrono::milliseconds>(duration).count() << " ms)";
        std::cout << std::endl;
    }

    std::cout << "Tests: " << pass << " pass, " << fail << " fail";
    const auto allEnd = std::chrono::high_resolution_clock::now();
    if (const auto duration = allEnd - allStart; duration > std::chrono::milliseconds{1})
        std::cout << " (" << std::chrono::duration_cast<std::chrono::milliseconds>(duration).count() << " ms)";
    std::cout << std::endl;

    return !fail;
}
