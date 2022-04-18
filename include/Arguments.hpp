#ifndef BKCRACK_ARGUMENTS_HPP
#define BKCRACK_ARGUMENTS_HPP

#include <map>

#include "types.hpp"
#include "Keys.hpp"
#include "Data.hpp"

/// Parse and store arguments
class Arguments
{
    public:
        /// Exception thrown if an argument is not valid
        class Error : public BaseError
        {
            public:
                /// Constructor
                Error(const std::string& description);
        };

        /// \brief Constructor parsing command line arguments
        /// \exception Error if an argument is not valid
        Arguments(int argc, const char* argv[]);

        /// \brief Load the data needed for an attack based on parsed arguments
        /// \exception FileError if a file cannot be opened
        /// \exception ZipError if a zip entry cannot be opened
        /// \exception Data::Error if the loaded data cannot be used to carry out an attack
        Data loadData() const;

        std::string cipherfile, ///< File containing the ciphertext
            cipherarchive,      ///< Zip archive containing cipherfile
            plainfile,          ///< File containing the known plaintext
            plainarchive,       ///< Zip archive containing plainfile
            decipheredfile,     ///< File to write the deciphered text
            unlockedarchive;    ///< File to write the encryped archive with the new password

        std::string infoarchive; ///< Zip archive about which to display information

        /// Plaintext offset relative to ciphertext without encryption header (may be negative)
        int offset = 0;

        /// \brief Maximum number of bytes of plaintext to read
        ///
        /// Set to 1 MiB by default. Using more plaintext is possible,
        /// but it uses more RAM and does not speed up the attack much.
        std::size_t plainsize = 1<<20;

        /// Additional bytes of plaintext with their offset relative to ciphertext without encryption header (may be negative)
        std::map<int, byte> extraPlaintext;

        /// Tell whether to try all candidate keys exhaustively or stop after the first success
        bool exhaustive = false;

        Keys keys; ///< Internal password representation
        bool keysGiven = false; ///< Tell whether keys were given or not

        std::string newPassword; ///< Password chosen to generate the unlocked archive

        std::size_t maxLength = 0; ///< Maximum password length to try during password recovery
        bytevec charset; ///< Characters to generate password candidates

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
        bytevec readHex(const std::string& description);
        uint32 readKey(const std::string& description);
        Keys readKeys();
        bytevec readCharset();
};

#endif // BKCRACK_ARGUMENTS_HPP
