#ifndef BKCRACK_KEYS_HPP
#define BKCRACK_KEYS_HPP

#include <iostream>

#include "types.hpp"

/// Keys defining the cipher state
class Keys
{
    public:
        /// Constructor
        Keys(uint32 x = 0x12345678, uint32 y = 0x23456789, uint32 z = 0x34567890);

        /// Construct keys associated to the given password
        Keys(const std::string& password);

        /// Update the state with a plaintext byte
        void update(byte p);

        /// Update the state forward to a target offset
        void update(const bytevec& ciphertext, std::size_t current, std::size_t target);

        /// Update the state backward with a ciphertext byte
        void updateBackward(byte c);

        /// Update the state backward to a target offset
        void updateBackward(const bytevec& ciphertext, std::size_t current, std::size_t target);

        /// \return X value
        uint32 getX() const;

        /// \return Y value
        uint32 getY() const;

        /// \return Z value
        uint32 getZ() const;

    private:
        uint32 x, y, z;
};

/// \brief Insert a representation of keys into the stream \a os
/// \relates Keys
std::ostream& operator<<(std::ostream& os, const Keys& keys);

#endif // BKCRACK_KEYS_HPP
