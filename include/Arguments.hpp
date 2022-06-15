#ifndef BKCRACK_ARGUMENTS_HPP
#define BKCRACK_ARGUMENTS_HPP

#include <map>
#include <optional>

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

        std::optional<std::string> cipherFile;    ///< File containing the ciphertext
        std::optional<std::size_t> cipherIndex;   ///< Index of the zip entry containing ciphertext
        std::optional<std::string> cipherArchive; ///< Zip archive containing \ref cipherFile

        std::optional<std::string> plainFile;     ///< File containing the known plaintext
        std::optional<std::size_t> plainIndex;    ///< Index of the zip entry containing plaintext
        std::optional<std::string> plainArchive;  ///< Zip archive containing \ref plainFile

        /// \brief Maximum number of bytes of plaintext to read from \ref plainFile
        ///
        /// Set to 1 MiB by default. Using more plaintext is possible,
        /// but it uses more RAM and does not speed up the attack much.
        std::size_t plainFilePrefix = 1 << 20;

        /// Plaintext offset relative to ciphertext without encryption header (may be negative)
        int offset = 0;

        /// Additional bytes of plaintext with their offset relative to ciphertext without encryption header (may be negative)
        std::map<int, byte> extraPlaintext;

        /// Tell not to use the check byte derived from ciphertext entry metadata as known plaintext
        bool ignoreCheckByte = false;

        /// Tell whether to try all candidate keys exhaustively or stop after the first success
        bool exhaustive = false;

        /// Internal password representation
        std::optional<Keys> keys;

        /// File to write the deciphered text corresponding to \ref cipherFile
        std::optional<std::string> decipheredFile;

        /// Arguments needed to change an archive's password
        struct ChangePassword
        {
            std::string unlockedArchive; ///< File to write the new encrypted archive
            std::string newPassword;     ///< Password chosen to generate the new archive
        };
        /// \copydoc ChangePassword
        std::optional<ChangePassword> changePassword;

        /// \brief Arguments needed to change an archive's internal password representation
        ///
        /// Changing the internal password representation is an alternative to changing the password
        /// when the target password is not known, but its internal representation is known.
        struct ChangeKeys
        {
            std::string unlockedArchive; ///< File to write the new encrypted archive
            Keys newKeys;                ///< Internal password representation chosen to generate the new archive
        };
        /// \copydoc ChangeKeys
        std::optional<ChangeKeys> changeKeys;

        /// Arguments needed to attempt a password recovery
        struct PasswordRecovery
        {
            std::size_t maxLength; ///< Maximum password length to try during password recovery
            bytevec charset;       ///< Characters to generate password candidates
        };
        /// \copydoc PasswordRecovery
        std::optional<PasswordRecovery> recoverPassword;

        /// Zip archive about which to display information
        std::optional<std::string> infoArchive;

        /// Tell whether help message is needed or not
        bool help = false;

    private:
        const char** m_current;
        const char** const m_end;

        bool finished() const;

        void parseArgument();

        enum class Option
        {
            cipherFile,
            cipherIndex,
            cipherArchive,
            plainFile,
            plainIndex,
            plainArchive,
            plainFilePrefix,
            offset,
            extraPlaintext,
            ignoreCheckByte,
            exhaustive,
            keys,
            decipheredFile,
            changePassword,
            changeKeys,
            recoverPassword,
            infoArchive,
            help
        };

        std::string readString(const std::string& description);
        Option readOption(const std::string& description);
        int readInt(const std::string& description);
        std::size_t readSize(const std::string& description);
        bytevec readHex(const std::string& description);
        uint32 readKey(const std::string& description);
        bytevec readCharset();
};

#endif // BKCRACK_ARGUMENTS_HPP
