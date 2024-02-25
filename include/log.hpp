#ifndef BKCRACK_LOG_HPP
#define BKCRACK_LOG_HPP

#include <iostream>

/// \file log.hpp
/// \brief Output stream manipulators

/// Insert the current local time into the output stream
auto put_time(std::ostream& os) -> std::ostream&;

class Keys; // forward declaration

/// \brief Insert a representation of keys into the stream \a os
/// \relates Keys
auto operator<<(std::ostream& os, const Keys& keys) -> std::ostream&;

#endif // BKCRACK_LOG_HPP
