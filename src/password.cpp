#include "password.hpp"
#include "Crc32Tab.hpp"
#include "MultTab.hpp"

Recovery::Recovery(const Keys& keys, const bytevec& charset, Progress& progress)
: charset(charset), progress(progress)
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

bool Recovery::recoverShortPassword()
{
    Keys initial;

    for(int length = 6; length >= 0; length--)
    {
        if(recover(initial))
        {
            password.erase(0, 6 - length);
            return true;
        }

        initial.updateBackwardPlaintext(charset.front());
    }

    return false;
}

bool Recovery::recoverLongPassword(const Keys& initial, std::size_t length)
{
    if(length == 7)
    {
        if(!zm1_24_32[initial.getZ() >> 24])
            return false;

        for(byte pi : charset)
        {
            Keys init = initial;
            init.update(pi);

            if(recover(init))
            {
                password.insert(password.begin(), pi);
                return true;
            }
        }
    }
    else
    {
        if(progress.state != Progress::State::Normal)
            return false;

        for(byte pi : charset)
        {
            Keys init = initial;
            init.update(pi);

            if(recoverLongPassword(init, length-1))
            {
                password.insert(password.begin(), pi);
                return true;
            }
        }
    }

    return false;
}

const std::string& Recovery::getPassword() const
{
    return password;
}

bool Recovery::recover(const Keys& initial)
{
    // check compatible Z0[16,32)
    if(!z0_16_32[initial.getZ() >> 16])
        return false;

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
    return recursion(5);
}

bool Recovery::recursion(int i)
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

                if(recursion(i-1))
                    return true;
            }
        }
    }
    else // the Y-list is complete
    {
        // only the X1 LSB was not set yet, so do it here
        x[1] = (y[1] - 1) * MultTab::MULTINV - y[0];
        if(x[1] > 0xff)
            return false;

        // complete X values and derive password
        for(int i = 5; 0 <= i; i--)
        {
            uint32 xi_xor_pi = Crc32Tab::crc32inv(x[i+1], 0);
            p[i] = lsb(xi_xor_pi ^ x[i]);
            x[i] = xi_xor_pi ^ p[i];
        }

        if(x[0] == x0) // the password is successfully recovered
        {
            password.assign(p.begin(), p.end());
            return true;
        }
    }

    return false;
}

bool recoverPassword(const Keys& keys, std::size_t max_length, const bytevec& charset, std::string& password, Progress& progress)
{
    Recovery worker(keys, charset, progress);

    // look for a password of length between 0 and 6
    progress.log([](std::ostream& os) { os << "length 0-6..." << std::endl; });

    if(worker.recoverShortPassword())
    {
        password = worker.getPassword();
        progress.state = Progress::State::EarlyExit;
        return true;
    }

    // look for a password of length between 7 and 9
    for(std::size_t length = 7; length < 10 && length <= max_length; length++)
    {
        progress.log([length](std::ostream& os) { os << "length " << length << "..." << std::endl; });

        if(worker.recoverLongPassword(Keys{}, length))
        {
            password = worker.getPassword();
            progress.state = Progress::State::EarlyExit;
            return true;
        }
    }

    // look for a password of length between 10 and max_length
    // same as above, but in a parallel loop
    for(std::size_t length = 10; length <= max_length; length++)
    {
        const int charsetSize = charset.size();

        std::atomic<bool> found = false;
        progress.done = 0;
        progress.total = charsetSize * charsetSize;

        progress.log([length](std::ostream& os) { os << "length " << length << "..." << std::endl; });

        // bruteforce two characters to have many tasks for each CPU thread and share work evenly
        #pragma omp parallel for firstprivate(worker) schedule(dynamic)
        for(std::int32_t i = 0; i < charsetSize * charsetSize; i++)
        {
            if(progress.state != Progress::State::Normal)
                continue; // cannot break out of an OpenMP for loop

            Keys init;
            init.update(charset[i / charsetSize]);
            init.update(charset[i % charsetSize]);

            if(worker.recoverLongPassword(init, length - 2))
            {
                password = worker.getPassword();
                password.insert(password.begin(), charset[i % charsetSize]);
                password.insert(password.begin(), charset[i / charsetSize]);
                found = true;
                progress.state = Progress::State::EarlyExit;
            }

            progress.done++;
        }

        if(found)
            return true;
    }

    return false;
}
