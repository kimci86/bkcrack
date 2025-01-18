#ifndef BKCRACK_ARGUMENTS_HPP
#define BKCRACK_ARGUMENTS_HPP

#include "Data.hpp"
#include "Keys.hpp"
#include "types.hpp"

#include <limits>
#include <map>
#include <optional>
#include <unordered_map>

/// Parse and store arguments
class Arguments
{
public:
    /// Exception thrown if an argument is not valid
    class Error : public BaseError
    {
    public:
        /// Constructor
        explicit Error(const std::string& description);
    };

    /// \brief Constructor parsing command line arguments
    /// \exception Error if an argument is not valid
    Arguments(int argc, const char* argv[]);

    /// \brief Load the data needed for an attack based on parsed arguments
    /// \exception FileError if a file cannot be opened
    /// \exception ZipError if a zip entry cannot be opened
    /// \exception Data::Error if the loaded data cannot be used to carry out an attack
    auto loadData() const -> Data;

    std::optional<std::string> cipherFile;    ///< File containing the ciphertext
    std::optional<std::size_t> cipherIndex;   ///< Index of the zip entry containing ciphertext
    std::optional<std::string> cipherArchive; ///< Zip archive containing \ref cipherFile

    std::optional<std::string> plainFile;    ///< File containing the known plaintext
    std::optional<std::size_t> plainIndex;   ///< Index of the zip entry containing plaintext
    std::optional<std::string> plainArchive; ///< Zip archive containing \ref plainFile

    /// \brief Maximum number of bytes of plaintext to read from \ref plainFile
    ///
    /// Set to 1 MiB by default. Using more plaintext is possible,
    /// but it uses more RAM and does not speed up the attack much.
    std::size_t plainFilePrefix = 1 << 20;

    /// Plaintext offset relative to ciphertext without encryption header (may be negative)
    int offset = 0;

    /// Additional bytes of plaintext with their offset relative to ciphertext without encryption header (may be
    /// negative)
    std::map<int, std::uint8_t> extraPlaintext;

    /// Tell not to use the check byte derived from ciphertext entry metadata as known plaintext
    bool ignoreCheckByte = false;

    /// Staring point of the attack on Z values remaining after reduction
    int attackStart = 0;

    /// Password from which to derive the internal password representation
    std::optional<std::string> password;

    /// Internal password representation
    std::optional<Keys> keys;

    /// File to write the deciphered text corresponding to \ref cipherFile
    std::optional<std::string> decipheredFile;

    /// Tell whether to keep the encryption header or discard it when writing the deciphered text
    bool keepHeader = false;

    /// File to write an unencrypted copy of the encrypted archive
    std::optional<std::string> decryptedArchive;

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
        Keys        newKeys;         ///< Internal password representation chosen to generate the new archive
    };
    /// \copydoc ChangeKeys
    std::optional<ChangeKeys> changeKeys;

    /// Characters to generate password candidates
    std::optional<std::vector<std::uint8_t>> bruteforce;

    /// Range of password lengths to try during password recovery
    struct LengthInterval
    {
        /// Smallest password length to try (inclusive)
        std::size_t minLength{0};

        /// Greatest password length to try (inclusive)
        std::size_t maxLength{std::numeric_limits<std::size_t>::max()};

        /// Compute the intersection between this interval and the given \a other interval
        auto operator&(const LengthInterval& other) const -> LengthInterval;
    };
    /// \copydoc LengthInterval
    std::optional<LengthInterval> length;

    /// Starting point for password recovery
    std::string recoveryStart;

    /// Number of threads to use for parallelized operations
    int jobs;

    /// Tell whether to try all candidates (keys or passwords) exhaustively or stop after the first success
    bool exhaustive = false;

    /// Zip archive about which to display information
    std::optional<std::string> infoArchive;

    /// Tell whether version information is needed or not
    bool version = false;

    /// Tell whether help message is needed or not
    bool help = false;

private:
    const char**       m_current;
    const char** const m_end;

    std::unordered_map<char, std::bitset<256>> m_charsets;
    std::unordered_map<char, std::string>      m_rawCharsets;

    auto resolveCharset(const std::string& rawCharset) -> std::bitset<256>;

    std::optional<std::string> m_rawBruteforce;

    auto finished() const -> bool;

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
        attackStart,
        password,
        keys,
        decipheredFile,
        keepHeader,
        decryptedArchive,
        changePassword,
        changeKeys,
        bruteforce,
        length,
        recoverPassword,
        charset,
        recoveryStart,
        jobs,
        exhaustive,
        infoArchive,
        version,
        help
    };

    auto readString(const std::string& description) -> std::string;
    auto readOption(const std::string& description) -> Option;
    auto readInt(const std::string& description) -> int;
    auto readSize(const std::string& description) -> std::size_t;
    auto readHex(const std::string& description) -> std::vector<std::uint8_t>;
    auto readKey(const std::string& description) -> std::uint32_t;
    auto readRawCharset(const std::string& description) -> std::string;
};

#endif // BKCRACK_ARGUMENTS_HPP
