#ifndef BKCRACK_FILE_HPP
#define BKCRACK_FILE_HPP

/// \file file.hpp
/// \brief Opening files and loading raw data
///
/// This graph shows how functions from this file work together:
/// \dot
/// digraph {
///     node [ fontsize=10 ];
///     edge [ fontsize=10 ];
///
///     input [ label="filename" ];
///     output [ label="filename" ];
///     bytevec [ URL="\ref bytevec" ];
///
///     input -> "std::ifstream" [ label="openInput", URL="\ref openInput"];
///     "std::ifstream" -> bytevec [ label="loadStream", URL="\ref loadStream"];
///     input -> bytevec [ label="loadFile", URL="\ref loadFile"];
///
///     output -> "std::ofstream" [ label="openOutput", URL="\ref openOutput"];
/// }
/// \enddot

#include <fstream>

#include "types.hpp"

/// Exception thrown if a file cannot be opened
class FileError : public BaseError
{
    public:
        /// Constructor
        FileError(const std::string& description);
};

/// \brief Open an input file stream
/// \exception FileError if the file cannot be opened
std::ifstream openInput(const std::string& filename);

/// Load at most \a size bytes from an input stream
bytevec loadStream(std::istream& is, std::size_t size);

/// \brief Load at most \a size bytes from a file
/// \exception FileError if the file cannot be opened
bytevec loadFile(const std::string& filename, std::size_t size);

/// \brief Open an output file stream
/// \exception FileError if the file cannot be opened
std::ofstream openOutput(const std::string& filename);

#endif // BKCRACK_FILE_HPP
