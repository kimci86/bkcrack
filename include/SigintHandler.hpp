#ifndef BKCRACK_SIGINTHANDLER_HPP
#define BKCRACK_SIGINTHANDLER_HPP

#include "Progress.hpp"

/// \brief Utility class to set a progress state to Progress::State::Canceled when SIGINT arrives
///
/// \note There should exist at most one instance of this class at any time.
class SigintHandler
{
public:
    /// Enable the signal handler
    SigintHandler(std::atomic<Progress::State>& destination);

    /// Disable the signal handler
    ~SigintHandler();

    /// Deleted copy constructor
    SigintHandler(const SigintHandler& other) = delete;

    /// Deleted assignment operator
    SigintHandler& operator=(const SigintHandler& other) = delete;
};

#endif // BKCRACK_SIGINTHANDLER_HPP
