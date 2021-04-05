#ifndef BKCRACK_LOG_HPP
#define BKCRACK_LOG_HPP

#include <iostream>

/// \file log.hpp
/// \brief Output stream manipulators

/// Setup format flags for logging and show version information
std::ostream& setupLog(std::ostream& os);

/// Insert the current local time into the output stream
std::ostream& put_time(std::ostream& os);

/// Manipulator to insert a progress representation
class progress
{
    public:
        /// Constructor
        progress(int num, int den);

        /// Insert the progress into the output stream
        std::ostream& operator()(std::ostream& os) const;

    private:
        int num, den;
};

/// \brief Insert a progress manipulator into the output stream
/// \relates progress
std::ostream& operator<<(std::ostream& os, const progress& p);

#endif // BKCRACK_LOG_HPP
