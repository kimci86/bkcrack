#include "SigintHandler.hpp"
#include <csignal>

namespace
{

static_assert(std::atomic<Progress::State>::is_always_lock_free, "atomics must be lock-free to be signal-safe");

std::atomic<Progress::State>* destination = nullptr;

} // namespace

void bkcrackSigintHandler(int sig)
{
    *destination = Progress::State::Canceled;
    std::signal(sig, &bkcrackSigintHandler);
}

SigintHandler::SigintHandler(std::atomic<Progress::State>& destination)
{
    ::destination = &destination;
    std::signal(SIGINT, &bkcrackSigintHandler);
}

SigintHandler::~SigintHandler()
{
    std::signal(SIGINT, SIG_DFL);
    destination = nullptr;
}
