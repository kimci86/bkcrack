#ifndef BKCRACK_FILE_HPP
#define BKCRACK_FILE_HPP

#include <fstream>

#include "types.hpp"

/// Exception thrown if a file cannot be opened
class FileError : public BaseError
{
    public:
        /// Constructor
        FileError(const std::string& description);
};

/// Open an input file stream
///
/// \exception FileError if the file cannot be opened
std::ifstream openInput(const std::string& filename);

/// Load at most \a size bytes from an input stream
bytevec loadStream(std::istream& is, std::size_t size);

/// Load at most \a size bytes from a file
///
/// \exception FileError if the file cannot be opened
bytevec loadFile(const std::string& filename, std::size_t size);

/// Open an output file stream
///
/// \exception FileError if the file cannot be opened
std::ofstream openOutput(const std::string& filename);

#endif // BKCRACK_FILE_HPP
