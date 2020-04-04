#ifndef BKCRACK_FILE_HPP
#define BKCRACK_FILE_HPP

#include <fstream>
#include <limits>

#include "types.hpp"

/// Exception thrown if a file can not be opened
class FileError : public BaseError
{
    public:
        /// Constructor
        FileError(const std::string& description);
};

/// Open an input file stream
///
/// \exception FileError if the file can not be opened
std::ifstream openInput(std::string filename);

/// Open an input file stream ready to read a zip archive entry data
///
/// \exception FileError if the file can not be opened or the entry does not exist
std::ifstream openInputZipEntry(const std::string archivename, const std::string& entryname, std::size_t& size);

/// Open an output file stream
///
/// \exception FileError if the file can not be opened
std::ofstream openOutput(std::string filename);

/// Load at most \a size bytes from an input stream
bytevec loadStream(std::istream& is, std::size_t size = std::numeric_limits<std::size_t>::max());

/// Load at most \a size bytes from a file
///
/// \exception FileError if the file can not be opened
bytevec loadFile(std::string filename, std::size_t size = std::numeric_limits<std::size_t>::max());

/// Load at most \a size bytes from a zip archive entry
///
/// \exception FileError if the file can not be opened or the entry does not exist
bytevec loadZipEntry(const std::string archivename, const std::string& entryname, std::size_t size = std::numeric_limits<std::size_t>::max());

#endif // BKCRACK_FILE_HPP
