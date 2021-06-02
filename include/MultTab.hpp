#ifndef BKCRACK_MULTTAB_HPP
#define BKCRACK_MULTTAB_HPP

#include "types.hpp"

/// Lookup tables for multiplication related computations
class MultTab
{
    public:
        /// \return MULT^-1 * x using a lookup table
        static inline uint32 getMultinv(byte x)
        {
            return instance.multinvtab[x];
        }

        /// \return a vector of bytes x such that
        /// msb(x*MULT^-1) is equal to msbprod or msbprod-1
        static inline const bytevec& getMsbProdFiber2(byte msbprodinv)
        {
            return instance.msbprodfiber2[msbprodinv];
        }

        /// \return a vector of bytes x such that
        /// msb(x*MULT^-1) is equal to msbprod, msbprod-1 or msbprod+1
        static inline const bytevec& getMsbProdFiber3(byte msbprodinv)
        {
            return instance.msbprodfiber3[msbprodinv];
        }

        enum : uint32
        {
            MULT    = 0x08088405,
            MULTINV = 0xd94fa8cd
        };

    private:
        // initialize lookup tables
        MultTab();

        // lookup tables
        u32arr<256> multinvtab;
        std::array<bytevec, 256> msbprodfiber2;
        std::array<bytevec, 256> msbprodfiber3;

        static const MultTab instance;
};

#endif // BKCRACK_MULTTAB_HPP
