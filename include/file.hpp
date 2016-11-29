#ifndef BKCRACK_FILE_HPP
#define BKCRACK_FILE_HPP

#include <fstream>
#include <stdexcept>

/// Exception thrown if a file can not be opened
class FileError : public std::runtime_error
{
    public:
        /// Constructor
        FileError(const std::string& description);
};

/// Open an input file stream
///
/// \exception FileError if the file can not be opened
std::ifstream openInput(std::string filename);

/// Open an output file stream
///
/// \exception FileError if the file can not be opened
std::ofstream openOutput(std::string filename);

#endif // BKCRACK_FILE_HPP
