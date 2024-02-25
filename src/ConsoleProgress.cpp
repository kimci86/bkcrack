#include "ConsoleProgress.hpp"

#include "log.hpp"

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
        if (const auto total = this->total.load())
            log(
                [done = done.load(), total](std::ostream& os)
                {
                    const auto flagsBefore     = os.setf(std::ios::fixed, std::ios::floatfield);
                    const auto precisionBefore = os.precision(1);

                    os << (100.0 * done / total) << " % (" << done << " / " << total << ")" << std::flush
                       << "\033[1K\r";

                    os.precision(precisionBefore);
                    os.flags(flagsBefore);
                });

        auto lock = std::unique_lock{m_in_destructor_mutex};
        repeat    = !m_in_destructor_cv.wait_for(lock, m_interval, [this] { return m_in_destructor; });
    }

    if (const auto total = this->total.load())
        log(
            [done = done.load(), total](std::ostream& os)
            {
                const auto flagsBefore     = os.setf(std::ios::fixed, std::ios::floatfield);
                const auto precisionBefore = os.precision(1);

                os << (100.0 * done / total) << " % (" << done << " / " << total << ")" << std::endl;

                os.precision(precisionBefore);
                os.flags(flagsBefore);
            });
}
