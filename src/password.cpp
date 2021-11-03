#include "password.hpp"
#include "log.hpp"
#include "Crc32Tab.hpp"
#include "MultTab.hpp"

static const char* erase_line = "                       \r";

Recovery::Recovery(const Keys& keys, const bytevec& charset, std::vector<std::string>& solutions,
                   bool exhaustive, std::atomic<bool>& stop)
: charset(charset), solutions(solutions), exhaustive(exhaustive), stop(stop)
{
    // initialize target X, Y and Z values
    x[6] = keys.getX();
    y[6] = keys.getY();
    z[6] = keys.getZ();

    // derive Y5
    y[5] = (y[6] - 1) * MultTab::MULTINV - lsb(x[6]);

    // derive more Z bytes
    for(int i = 6; 1 < i; i--)
        z[i-1] = Crc32Tab::crc32inv(z[i], msb(y[i]));

    // precompute possible Z0[16,32) and Z{-1}[24,32)
    for(byte p5 : charset)
    {
        x[5] = Crc32Tab::crc32inv(x[6], p5);
        y[4] = (y[5] - 1) * MultTab::MULTINV - lsb(x[5]);
        z[3] = Crc32Tab::crc32inv(z[4], msb(y[4]));

        for(byte p4 : charset)
        {
            x[4] = Crc32Tab::crc32inv(x[5], p4);
            y[3] = (y[4] - 1) * MultTab::MULTINV - lsb(x[4]);
            z[2] = Crc32Tab::crc32inv(z[3], msb(y[3]));
            z[1] = Crc32Tab::crc32inv(z[2], 0);
            z[0] = Crc32Tab::crc32inv(z[1], 0);

            z0_16_32.set(z[0] >> 16);
            zm1_24_32.set(Crc32Tab::crc32inv(z[0], 0) >> 24);
        }
    }
}

void Recovery::recoverShortPassword(std::size_t length)
{
    Keys initial;

    for(int i = 0; i < 6 - length; i++)
        initial.updateBackwardPlaintext(charset.front());

    prefix.clear();
    erase = 6 - length;

    recover(initial);
}

void Recovery::recoverLongPassword(const std::string& prefix, std::size_t length)
{
    this->prefix = prefix;
    erase = 0;

    recoverLongPassword(Keys(prefix), length - prefix.size());
}

void Recovery::recoverLongPassword(const Keys& initial, std::size_t length)
{
    if(length == 7)
    {
        if(!zm1_24_32[initial.getZ() >> 24])
            return;

        prefix.push_back(charset.front());

        for(byte pi : charset)
        {
            Keys init = initial;
            init.update(pi);

            prefix.back() = pi;
            recover(init);
        }

        prefix.pop_back();
    }
    else
    {
        if(stop)
            return;

        prefix.push_back(charset.front());

        for(byte pi : charset)
        {
            Keys init = initial;
            init.update(pi);

            prefix.back() = pi;
            recoverLongPassword(init, length-1);
        }

        prefix.pop_back();
    }
}

void Recovery::recover(const Keys& initial)
{
    // check compatible Z0[16,32)
    if(!z0_16_32[initial.getZ() >> 16])
        return;

    // initialize starting X, Y and Z values
    x[0] = x0 = initial.getX();
    y[0] = initial.getY();
    z[0] = initial.getZ();

    // complete Z values and derive Y[24,32) values
    for(int i = 1; i <= 4; i++)
    {
        y[i] = Crc32Tab::getYi_24_32(z[i], z[i-1]);
        z[i] = Crc32Tab::crc32(z[i-1], msb(y[i]));
    }

    // recursively complete Y values and derive password
    recursion(5);
}

void Recovery::recursion(int i)
{
    if(i != 1) // the Y-list is not complete so generate Y{i-1} values
    {
        uint32 fy = (y[i] - 1) * MultTab::MULTINV;
        uint32 ffy = (fy - 1) * MultTab::MULTINV;

        // get possible LSB(Xi)
        for(byte xi_0_8 : MultTab::getMsbProdFiber2(msb(ffy - (y[i-2] & MASK_24_32))))
        {
            // compute corresponding Y{i-1}
            uint32 yim1 = fy - xi_0_8;

            // filter values with Y{i-2}[24,32)
            if(ffy - MultTab::getMultinv(xi_0_8) - (y[i-2] & MASK_24_32) <= MAXDIFF_0_24
                && msb(yim1) == msb(y[i-1]))
            {
                // add Y{i-1} to the Y-list
                y[i-1] = yim1;

                // set Xi value
                x[i] = xi_0_8;

                recursion(i-1);
            }
        }
    }
    else // the Y-list is complete
    {
        // only the X1 LSB was not set yet, so do it here
        x[1] = (y[1] - 1) * MultTab::MULTINV - y[0];
        if(x[1] > 0xff)
            return;

        // complete X values and derive password
        for(int i = 5; 0 <= i; i--)
        {
            uint32 xi_xor_pi = Crc32Tab::crc32inv(x[i+1], 0);
            p[i] = lsb(xi_xor_pi ^ x[i]);
            x[i] = xi_xor_pi ^ p[i];
        }

        if(x[0] == x0) // the password is successfully recovered
        {
            std::string password = (prefix + std::string(p.begin(), p.end())).erase(0, erase);

            #pragma omp critical
            {
                std::cout << erase_line << "Password: " << password << std::endl;
                solutions.push_back(password);
            }

            stop = !exhaustive;
        }
    }
}

std::vector<std::string> recoverPassword(const Keys& keys, const bytevec& charset,
    std::size_t min_length, std::size_t max_length, bool exhaustive, std::atomic<Progress>* progress)
{
    std::vector<std::string> solutions;
    std::atomic<bool> stop(false);
    Recovery worker(keys, charset, solutions, exhaustive, stop);

    const int charsetSize = charset.size();

    for(std::size_t length = min_length; length <= max_length && !stop; length++)
    {
        std::cout << erase_line << "length " << length << std::endl;
        if(length <= 6)
            worker.recoverShortPassword(length);
        else if(length < 10)
            worker.recoverLongPassword("", length);
        else
        {
            int done = 0;

            std::string prefix(2, charset.front());

            if(progress)
                *progress = {0, charsetSize * charsetSize};

            // bruteforce two characters to have many tasks for each CPU thread and share work evenly
            #pragma omp parallel for firstprivate(worker, prefix) schedule(dynamic)
            for(std::int32_t i = 0; i < charsetSize * charsetSize; i++)
            {
                if(stop)
                    continue; // cannot break out of an OpenMP for loop

                prefix[0] = charset[i / charsetSize];
                prefix[1] = charset[i % charsetSize];

                worker.recoverLongPassword(prefix, length);

                if(progress)
                    #pragma omp critical
                    *progress = {++done, charsetSize * charsetSize};
            }
        }
    }

    return solutions;
}
