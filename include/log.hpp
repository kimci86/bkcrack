#ifndef BKCRACK_LOG_HPP
#define BKCRACK_LOG_HPP

#include <iostream>
#include <mutex>
#include <condition_variable>
#include <thread>

#include "types.hpp"

/// \file log.hpp
/// \brief Logging utilities

/// Setup format flags for logging and show version information
std::ostream& setupLog(std::ostream& os);

/// Insert the current local time into the output stream
std::ostream& put_time(std::ostream& os);

/// Class to print a progress indicator at regular time intervals
class ProgressPrinter
{
    public:
        /// Start a thread to print progress
        ProgressPrinter(std::ostream& os, const std::chrono::milliseconds& interval = std::chrono::milliseconds(500));

        /// Notify and stop the printing thread
        ~ProgressPrinter();

        /// \brief Progress printed at regular time intervals
        ///
        /// This object is meant to be updated by a long operation running concurrently.
        std::atomic<Progress> progress;

    private:
        std::ostream& m_os;
        const std::chrono::milliseconds m_interval;

        std::mutex m_running_mutex;
        std::condition_variable m_running_cv;
        bool m_running;

        std::thread m_printer;
};

class Keys; // forward declaration

/// \brief Insert a representation of keys into the stream \a os
/// \relates Keys
std::ostream& operator<<(std::ostream& os, const Keys& keys);

#endif // BKCRACK_LOG_HPP
