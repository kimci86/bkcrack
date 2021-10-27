#ifndef BKCRACK_KEYS_HPP
#define BKCRACK_KEYS_HPP

#include "Crc32Tab.hpp"
#include "KeystreamTab.hpp"
#include "MultTab.hpp"

/// Keys defining the cipher state
class Keys
{
    public:
        /// Constructor
        Keys(uint32 x = 0x12345678, uint32 y = 0x23456789, uint32 z = 0x34567890);

        /// Construct keys associated to the given password
        Keys(const std::string& password);

        /// Update the state with a plaintext byte
        inline void update(byte p)
        {
            x = Crc32Tab::crc32(x, p);
            y = (y + lsb(x)) * MultTab::MULT + 1;
            z = Crc32Tab::crc32(z, msb(y));
        }

        /// Update the state forward to a target offset
        void update(const bytevec& ciphertext, std::size_t current, std::size_t target);

        /// Update the state backward with a ciphertext byte
        inline void updateBackward(byte c)
        {
            z = Crc32Tab::crc32inv(z, msb(y));
            y = (y - 1) * MultTab::MULTINV - lsb(x);
            x = Crc32Tab::crc32inv(x, c ^ getK());
        }

        /// Update the state backward with a plaintext byte
        inline void updateBackwardPlaintext(byte p)
        {
            z = Crc32Tab::crc32inv(z, msb(y));
            y = (y - 1) * MultTab::MULTINV - lsb(x);
            x = Crc32Tab::crc32inv(x, p);
        }

        /// Update the state backward to a target offset
        void updateBackward(const bytevec& ciphertext, std::size_t current, std::size_t target);

        /// \return X value
        uint32 getX() const { return x; }

        /// \return Y value
        uint32 getY() const { return y; }

        /// \return Z value
        uint32 getZ() const { return z; }

        /// \return the keystream byte derived from the keys
        byte getK() const { return KeystreamTab::getByte(z); }

    private:
        uint32 x, y, z;
};

#endif // BKCRACK_KEYS_HPP
