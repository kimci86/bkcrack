#include "ConsoleProgress.hpp"
#include "log.hpp"

ConsoleProgress::ConsoleProgress(std::ostream& os, const std::chrono::milliseconds& interval)
: Progress{os}, m_interval{interval}, m_in_destructor{false}, m_printer{&ConsoleProgress::printerFunction, this}
{}

ConsoleProgress::~ConsoleProgress()
{
    {
        std::scoped_lock lock{m_in_destructor_mutex};
        m_in_destructor = true;
    }

    m_in_destructor_cv.notify_all();
    m_printer.join();
}

void ConsoleProgress::printerFunction()
{
    bool repeat = true;

    // Give a small delay before the first time progress is printed so that
    // the running operation is likely to have initialized the total number of steps.
    {
        std::unique_lock<std::mutex> lock(m_in_destructor_mutex);
        repeat = !m_in_destructor_cv.wait_for(lock, std::chrono::milliseconds(1), [this]{ return m_in_destructor; });
    }

    while(repeat)
    {
        if(int total = this->total.load())
            log([done = done.load(), total](std::ostream& os)
            {
                os << (100.0 * done / (total ? total : 1)) << " % (" << done << " / " << total << ")" << std::flush << "\033[1K\r";
            });

        std::unique_lock<std::mutex> lock(m_in_destructor_mutex);
        repeat = !m_in_destructor_cv.wait_for(lock, m_interval, [this]{ return m_in_destructor; });
    }

    if(int total = this->total.load())
        log([done = done.load(), total](std::ostream& os)
        {
            os << (100.0 * done / (total ? total : 1)) << " % (" << done << " / " << total << ")" << std::endl;
        });
}
