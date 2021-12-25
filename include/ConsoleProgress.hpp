#ifndef BKCRACK_CONSOLEPROGRESS_HPP
#define BKCRACK_CONSOLEPROGRESS_HPP

#include <mutex>
#include <condition_variable>
#include <thread>

#include "Progress.hpp"

/// Progress indicator which prints itself at regular time intervals
class ConsoleProgress : public Progress
{
public:
    /// Start a thread to print progress
    ConsoleProgress(std::ostream& os, const std::chrono::milliseconds& interval = std::chrono::milliseconds(200));

    /// Notify and stop the printing thread
    ~ConsoleProgress();

private:
    const std::chrono::milliseconds m_interval;

    std::mutex m_in_destructor_mutex;
    std::condition_variable m_in_destructor_cv;
    bool m_in_destructor;

    std::thread m_printer;
    void printerFunction();
};

#endif // BKCRACK_CONSOLEPROGRESS_HPP
