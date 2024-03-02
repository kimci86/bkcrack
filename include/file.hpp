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
///     buffer [ label="std::vector<std::uint8_t>" ];
///
///     input -> "std::ifstream" [ label="openInput", URL="\ref openInput"];
///     "std::ifstream" -> buffer [ label="loadStream", URL="\ref loadStream"];
///     input -> buffer [ label="loadFile", URL="\ref loadFile"];
///
///     output -> "std::ofstream" [ label="openOutput", URL="\ref openOutput"];
/// }
/// \enddot

#include "types.hpp"

#include <fstream>

/// Exception thrown if a file cannot be opened
class FileError : public BaseError
{
public:
    /// Constructor
    explicit FileError(const std::string& description);
};

/// \brief Open an input file stream
/// \exception FileError if the file cannot be opened
auto openInput(const std::string& filename) -> std::ifstream;

/// Load at most \a size bytes from an input stream
auto loadStream(std::istream& is, std::size_t size) -> std::vector<std::uint8_t>;

/// \brief Load at most \a size bytes from a file
/// \exception FileError if the file cannot be opened
auto loadFile(const std::string& filename, std::size_t size) -> std::vector<std::uint8_t>;

/// \brief Open an output file stream
/// \exception FileError if the file cannot be opened
auto openOutput(const std::string& filename) -> std::ofstream;

#endif // BKCRACK_FILE_HPP
