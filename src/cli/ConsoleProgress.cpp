#include "ConsoleProgress.hpp"

#include <bkcrack/log.hpp>

#include <array>
#include <cstdio>

ConsoleProgress::ConsoleProgress(std::ostream& os, const std::chrono::milliseconds& interval)
: Progress{os}
, m_interval{interval}
, m_in_destructor{false}
, m_printer{&ConsoleProgress::printerFunction, this}
{
}

ConsoleProgress::~ConsoleProgress()
{
    {
        const auto lock = std::scoped_lock{m_in_destructor_mutex};
        m_in_destructor = true;
    }

    m_in_destructor_cv.notify_all();
    m_printer.join();
}

void ConsoleProgress::printerFunction()
{
    auto repeat = true;

    // Give a small delay before the first time progress is printed so that
    // the running operation is likely to have initialized the total number of steps.
    {
        auto lock = std::unique_lock{m_in_destructor_mutex};
        repeat = !m_in_destructor_cv.wait_for(lock, std::chrono::milliseconds{1}, [this] { return m_in_destructor; });
    }

    while (repeat)
    {
        if (const auto line = getProgressLine(); !line.empty())
            log([line](std::ostream& os)
                { os << line << std::flush << '\r' << std::string(line.size(), ' ') << '\r'; });

        auto lock = std::unique_lock{m_in_destructor_mutex};
        repeat    = !m_in_destructor_cv.wait_for(lock, m_interval, [this] { return m_in_destructor; });
    }

    if (const auto line = getProgressLine(); !line.empty())
        log([line](std::ostream& os) { os << line << std::endl; });
}

auto ConsoleProgress::getProgressLine() -> std::string
{
    if (const auto total = this->total.load())
    {
        const auto done   = this->done.load();
        auto       buffer = std::array<char, 80 + 1>{};
        const auto length =
            std::snprintf(buffer.data(), buffer.size(), "%.1f %% (%d / %d)", 100.0 * done / total, done, total);
        if (0 <= length && length < int{sizeof(buffer)})
            return std::string{buffer.data(), static_cast<std::size_t>(length)};
    }
    return "";
}
