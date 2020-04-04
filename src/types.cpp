#include "types.hpp"

BaseError::BaseError(const std::string& type, const std::string& description)
 : std::runtime_error(type + ": " + description + ".")
{}
