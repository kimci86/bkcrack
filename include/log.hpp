#ifndef BKCRACK_LOG_HPP
#define BKCRACK_LOG_HPP

#include <iostream>

/// \file log.hpp
/// \brief Output stream manipulators

/// Setup format flags for logging and show version information
std::ostream& setupLog(std::ostream& os);

/// Insert the current local time into the output stream
std::ostream& put_time(std::ostream& os);

class Keys; // forward declaration

/// \brief Insert a representation of keys into the stream \a os
/// \relates Keys
std::ostream& operator<<(std::ostream& os, const Keys& keys);

#endif // BKCRACK_LOG_HPP
