#include "log.hpp"
#include "version.hpp"
#include "Keys.hpp"
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

std::ostream& operator<<(std::ostream& os, const Keys& keys)
{
    return os << std::hex
              << std::setw(8) << keys.getX() << " "
              << std::setw(8) << keys.getY() << " "
              << std::setw(8) << keys.getZ()
              << std::dec;
}
