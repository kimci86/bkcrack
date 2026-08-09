#ifndef BKCRACK_PROGRESS_HPP
#define BKCRACK_PROGRESS_HPP

#include <atomic>
#include <concepts>
#include <iostream>
#include <mutex>

/// Structure to report the progress of a long operation or to cancel it
class Progress
{
public:
    /// Possible states of a long operation
    enum class State
    {
        Normal,   ///< The operation is ongoing or is fully completed
        Canceled, ///< The operation has been canceled externally
        EarlyExit ///< The operation stopped after a partial result was found
    };

    /// Constructor
    explicit Progress(std::ostream& os);

    /// Destructor
    virtual ~Progress() = default;

    /// Get exclusive access to the shared output stream and output progress
    /// information with the given function
    template <std::invocable<std::ostream&> F>
    void log(F f)
    {
        const auto lock = std::scoped_lock{m_os_mutex};
        beforeLog(m_os);
        f(m_os);
    }

    std::atomic<State> state = State::Normal; ///< State of the long operation
    std::atomic<int>   done  = 0;             ///< Number of steps already done
    std::atomic<int>   total = 0;             ///< Total number of steps

protected:
    virtual void beforeLog(std::ostream&) {}

    std::mutex    m_os_mutex;
    std::ostream& m_os;
};

#endif // BKCRACK_PROGRESS_HPP
