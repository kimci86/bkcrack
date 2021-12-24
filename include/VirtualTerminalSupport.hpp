#ifndef BKCRACK_VIRTUALTERMINALSUPPORT_HPP
#define BKCRACK_VIRTUALTERMINALSUPPORT_HPP

#include <memory>

/// \brief Class to enable virtual terminal support
///
/// It is useful only on Windows. It does nothing on other platforms.
class VirtualTerminalSupport
{
public:
    /// Enable virtual terminal support
    VirtualTerminalSupport();

    /// Restore console mode as it was before
    ~VirtualTerminalSupport();

private:
    class Impl; // platform-specific implementation

    std::unique_ptr<Impl> m_impl;
};

#endif // BKCRACK_VIRTUALTERMINALSUPPORT_HPP
