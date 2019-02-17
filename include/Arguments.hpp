#ifndef BKCRACK_ARGUMENTS_HPP
#define BKCRACK_ARGUMENTS_HPP

#include <stdexcept>
#include <limits>

#include "types.hpp"
#include "Keys.hpp"

/// Parse and store arguments
class Arguments
{
    public:
        /// Exception thrown if an argument is not valid
        class Error : public std::logic_error
        {
            public:
                /// Constructor
                Error(const std::string& description);
        };

        /// Parse command line arguments
        ///
        /// \exception Error if an argument is not valid
        void parse(int argc, const char* argv[]);

        std::string cipherfile, ///< File containing the ciphertext
            cipherarchive, ///< Zip archive containing cipherfile
            plainfile, ///< File containing the known plaintext
            plainarchive, ///< Zip archive containing plainfile
            decipheredfile; ///< File to write the deciphered text

        /// Plaintext offset relative to ciphertext without encryption header (may be negative)
        int offset = 0;
        /// Maximum number of bytes of plaintext to read
        std::size_t plainsize = std::numeric_limits<std::size_t>::max();

        Keys keys; ///< Internal password representation
        bool keysGiven = false; ///< Tell whether keys were given or not

        bool help = false; ///< Tell whether help message is needed or not

    private:
        int argc;
        const char** argv;
        const char** current;

        bool finished() const;

        void parseArgument();

        std::string readString(const std::string& description);
        char readFlag(const std::string& description);
        int readInt(const std::string& description);
        std::size_t readSize(const std::string& description);
        dword readKey(const std::string& description);
        Keys readKeys(const std::string& description);
};

#endif // BKCRACK_ARGUMENTS_HPP
