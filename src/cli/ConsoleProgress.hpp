#ifndef BKCRACK_CONSOLEPROGRESS_HPP
#define BKCRACK_CONSOLEPROGRESS_HPP

#include <bkcrack/Progress.hpp>

#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>

/// Progress indicator which prints itself at regular time intervals
class ConsoleProgress : public Progress
{
public:
    /// Start a thread to print progress
    explicit ConsoleProgress(std::ostream&                    os,
                             const std::chrono::milliseconds& interval = std::chrono::milliseconds{200});

    /// Notify and stop the printing thread
    ~ConsoleProgress();

private:
    const std::chrono::milliseconds m_interval;

    std::mutex              m_in_destructor_mutex;
    std::condition_variable m_in_destructor_cv;
    bool                    m_in_destructor;

    std::thread m_printer;
    void        printerFunction();

    void        beforeLog(std::ostream& os) override;
    std::size_t m_lengthToClear = 0;

    auto getProgressLine() -> std::string;
};

#endif // BKCRACK_CONSOLEPROGRESS_HPP
