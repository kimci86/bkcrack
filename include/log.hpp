#ifndef BKCRACK_LOG_HPP
#define BKCRACK_LOG_HPP

#include <iostream>

// output stream manipulators

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

/// Insert a progress manipulator into the output stream
std::ostream& operator<<(std::ostream& os, const progress& p);

#endif // BKCRACK_LOG_HPP
