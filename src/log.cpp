#include "log.hpp"
#include "version.hpp"
#include <ctime>
#include <iomanip>

std::ostream& setupLog(std::ostream& os)
{
    return os << std::setfill('0') // leading zeros for keys
              << std::fixed << std::setprecision(1) // for progress percentage
              << "bkcrack " BKCRACK_VERSION " - " BKCRACK_COMPILATION_DATE; // version information
}

std::ostream& put_time(std::ostream& os)
{
    std::time_t t = std::time(nullptr);
    return os << std::put_time(std::localtime(&t), "%T");
}

progress::progress(int num, int den)
 : num(num), den(den)
{}

std::ostream& progress::operator()(std::ostream& os) const
{
    return os << (100.0 * num / den) << " % (" << num << " / " << den << ")";
}

std::ostream& operator<<(std::ostream& os, const progress& p)
{
    return p(os);
}
