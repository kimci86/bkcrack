#include "password.hpp"
#include "Crc32Tab.hpp"
#include "MultTab.hpp"

Recovery::Recovery(const Keys& keys, const bytevec& charset, std::vector<std::string>& solutions, bool exhaustive, Progress& progress)
: charset(charset), solutions(solutions), exhaustive(exhaustive), progress(progress)
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

void Recovery::recoverShortPassword(const Keys& initial)
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

void Recovery::recoverLongPassword(const Keys& initial)
{
    if(prefix.size() + 7 == length) // there is only one more character to bruteforce
    {
        // check compatible Z{-1}[24, 32)
        if(!zm1_24_32[initial.getZ() >> 24])
            return;

        prefix.push_back(charset[0]);

        for(byte pi : charset)
        {
            Keys init = initial;
            init.update(pi);

            // recoverShortPassword is inlined below for performance

            // check compatible Z0[16,32)
            if(!z0_16_32[init.getZ() >> 16])
                continue;

            prefix.back() = pi;

            // initialize starting X, Y and Z values
            x[0] = x0 = init.getX();
            y[0] = init.getY();
            z[0] = init.getZ();

            // complete Z values and derive Y[24,32) values
            for(int i = 1; i <= 4; i++)
            {
                y[i] = Crc32Tab::getYi_24_32(z[i], z[i-1]);
                z[i] = Crc32Tab::crc32(z[i-1], msb(y[i]));
            }

            // recursively complete Y values and derive password
            recursion(5);
        }

        prefix.pop_back();
    }
    else // bruteforce the next character and continue recursively
    {
        prefix.push_back(charset[0]);

        for(byte pi : charset)
        {
            Keys init = initial;
            init.update(pi);

            prefix.back() = pi;

            recoverLongPassword(init);
        }

        prefix.pop_back();
    }
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
            std::string password = std::string(prefix.begin(), prefix.end());
            password.append(p.begin(), p.end());
            password.erase(password.begin(), password.end() - length);

            #pragma omp critical
            solutions.push_back(password);

            progress.log([&password](std::ostream& os)
            {
                os << "Password: " << password << std::endl;
            });

            if(!exhaustive)
                progress.state = Progress::State::EarlyExit;
        }
    }
}

namespace
{

void recoverPasswordRecursive(Recovery& worker, const Keys& initial, Progress& progress)
{
    if(worker.prefix.size() + 1 + 9 == worker.length) // bruteforce one character in parallel
    {
        const int charsetSize = worker.charset.size();

        worker.prefix.push_back(worker.charset[0]);

        #pragma omp parallel for firstprivate(worker) schedule(dynamic)
        for(int i = 0; i < charsetSize; i++)
        {
            if(progress.state != Progress::State::Normal)
                continue; // cannot break out of an OpenMP for loop

            byte pm4 = worker.charset[i];

            Keys init = initial;
            init.update(pm4);

            worker.prefix.back() = pm4;

            worker.recoverLongPassword(init);

            progress.done += charsetSize;
        }

        worker.prefix.pop_back();
    }
    else if(worker.prefix.size() + 2 + 9 == worker.length) // bruteforce two characters in parallel
    {
        const int charsetSize = worker.charset.size();

        worker.prefix.push_back(worker.charset[0]);
        worker.prefix.push_back(worker.charset[0]);

        const bool reportProgress = worker.prefix.size() == 2;
        const bool reportProgressCoarse = worker.prefix.size() == 3;

        #pragma omp parallel for firstprivate(worker) schedule(dynamic)
        for(int i = 0; i < charsetSize * charsetSize; i++)
        {
            if(progress.state != Progress::State::Normal)
                continue; // cannot break out of an OpenMP for loop

            byte pm4 = worker.charset[i / charsetSize];
            byte pm3 = worker.charset[i % charsetSize];

            Keys init = initial;
            init.update(pm4);
            init.update(pm3);

            worker.prefix[worker.prefix.size() - 2] = pm4;
            worker.prefix[worker.prefix.size() - 1] = pm3;

            worker.recoverLongPassword(init);

            if(reportProgress || (reportProgressCoarse && i % charsetSize == 0))
                progress.done++;
        }

        worker.prefix.pop_back();
        worker.prefix.pop_back();
    }
    else // try password prefixes recursively
    {
        worker.prefix.push_back(worker.charset[0]);

        const bool reportProgress = worker.prefix.size() == 2;

        for(byte pi : worker.charset)
        {
            Keys init = initial;
            init.update(pi);

            worker.prefix.back() = pi;

            recoverPasswordRecursive(worker, init, progress);

            // Because the recursive call may explore only a fraction of its
            // search space, check that it was run in full before counting progress.
            if(progress.state != Progress::State::Normal)
                break;

            if(reportProgress)
                progress.done++;
        }

        worker.prefix.pop_back();
    }
}

} // namespace

std::vector<std::string> recoverPassword(const Keys& keys, const bytevec& charset, std::size_t minLength, std::size_t maxLength, bool exhaustive, Progress& progress)
{
    std::vector<std::string> solutions;
    Recovery worker(keys, charset, solutions, exhaustive, progress);

    for(std::size_t length = minLength; length <= maxLength; length++)
    {
        if(progress.state != Progress::State::Normal)
            break;

        if(length <= 6)
        {
            progress.log([](std::ostream& os) { os << "length 0-6..." << std::endl; });

            Keys initial;

            // look for a password of length between 0 and 6
            for(int l = 6; l >= 0; l--)
            {
                worker.length = l;
                worker.recoverShortPassword(initial);

                initial.updateBackwardPlaintext(charset.front());
            }

            length = 6; // searching up to length 6 is done
        }
        else
        {
            progress.log([length](std::ostream& os) { os << "length " << length << "..." << std::endl; });

            worker.length = length;
            if(length < 10)
            {
                worker.recoverLongPassword(Keys{});
            }
            else
            {
                progress.done = 0;
                progress.total = charset.size() * charset.size();

                recoverPasswordRecursive(worker, Keys{}, progress);
            }
        }
    }

    return solutions;
}
