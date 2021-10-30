#include "log.hpp"
#include "version.hpp"
#include "Keys.hpp"
#include <ctime>
#include <iomanip>

std::ostream& setupLog(std::ostream& os)
{
    return os << std::setfill('0') // leading zeros for keys
              << std::fixed << std::setprecision(1) // for progress percentage
              << "bkcrack " BKCRACK_VERSION " - " BKCRACK_COMPILATION_DATE; // version information
}

std::ostream& put_time(std::ostream& os)
{
    std::time_t t = std::time(nullptr);
    return os << std::put_time(std::localtime(&t), "%T");
}

ProgressPrinter::ProgressPrinter(std::ostream& os, const std::chrono::milliseconds& interval)
: progress({0, 0}), m_os(os), m_interval(interval), m_running(true),
  m_printer([this]
    {
        bool done = false;

        while(true)
        {
            Progress p = progress;
            if(p.total)
                m_os << (100.0 * p.done / p.total) << " % (" << p.done << " / " << p.total << ")" << std::flush << '\r';

            if(done)
                break;

            std::unique_lock<std::mutex> lock(m_running_mutex);
            done = m_running_cv.wait_for(lock, m_interval, [this]{ return !m_running; });
        }
    })
{}

ProgressPrinter::~ProgressPrinter()
{
    {
        std::lock_guard<std::mutex> lock(m_running_mutex);
        m_running = false;
    }
    m_running_cv.notify_all();
    m_printer.join();
    if(progress.load().total)
        m_os << std::endl;
}

std::ostream& operator<<(std::ostream& os, const Keys& keys)
{
    return os << std::hex
              << std::setw(8) << keys.getX() << " "
              << std::setw(8) << keys.getY() << " "
              << std::setw(8) << keys.getZ()
              << std::dec;
}
