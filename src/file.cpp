#include "file.hpp"

FileError::FileError(const std::string& description)
 : std::runtime_error(description)
{}

std::ifstream openInput(std::string filename)
{
    if(std::ifstream is = std::ifstream(filename, std::ios::binary))
        return is;
    else
        throw FileError("Could not open input file " + filename);
}

std::ofstream openOutput(std::string filename)
{
    if(std::ofstream os = std::ofstream(filename, std::ios::binary))
        return os;
    else
        throw FileError("Could not open output file " + filename);
}
