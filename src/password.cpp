#include "password.hpp"

#include "Crc32Tab.hpp"
#include "MultTab.hpp"
#include "log.hpp"

#include <algorithm>
#include <atomic>
#include <bitset>
#include <iomanip>
#include <mutex>
#include <thread>

template <typename Derived /* must implement onSolutionFound() method */>
class SixCharactersRecovery
{
public:
    SixCharactersRecovery(const Keys& target, const std::vector<std::uint8_t>& charset4,
                          const std::vector<std::uint8_t>& charset5)
    {
        // initialize target X, Y and Z values
        x[6] = target.getX();
        y[6] = target.getY();
        z[6] = target.getZ();

        // derive Y5
        y[5] = (y[6] - 1) * MultTab::multInv - lsb(x[6]);

        // derive more Z bytes
        for (auto i = 6; 1 < i; i--)
            z[i - 1] = Crc32Tab::crc32inv(z[i], msb(y[i]));

        // precompute possible Z0[16,32) and Z{-1}[24,32)
        for (const auto p5 : charset5)
        {
            x[5] = Crc32Tab::crc32inv(x[6], p5);
            y[4] = (y[5] - 1) * MultTab::multInv - lsb(x[5]);
            z[3] = Crc32Tab::crc32inv(z[4], msb(y[4]));

            for (const auto p4 : charset4)
            {
                x[4] = Crc32Tab::crc32inv(x[5], p4);
                y[3] = (y[4] - 1) * MultTab::multInv - lsb(x[4]);
                z[2] = Crc32Tab::crc32inv(z[3], msb(y[3]));
                z[1] = Crc32Tab::crc32inv(z[2], 0);
                z[0] = Crc32Tab::crc32inv(z[1], 0);

                z0_16_32.set(z[0] >> 16);
                zm1_24_32.set(Crc32Tab::crc32inv(z[0], 0) >> 24);
            }
        }
    }

    void search(const Keys& initial)
    {
        // check compatible Z0[16,32)
        if (!z0_16_32[initial.getZ() >> 16])
            return;

        // initialize starting X, Y and Z values
        x[0] = candidateX0 = initial.getX();
        y[0]               = initial.getY();
        z[0]               = initial.getZ();

        // complete Z values and derive Y[24,32) values
        for (auto i = 1; i <= 4; i++)
        {
            y[i] = Crc32Tab::getYi_24_32(z[i], z[i - 1]);
            z[i] = Crc32Tab::crc32(z[i - 1], msb(y[i]));
        }

        // recursively complete Y values and derive password
        searchRecursive(5);
    }

protected:
    void searchRecursive(int i)
    {
        if (i != 1) // the Y-list is not complete so generate Y{i-1} values
        {
            const auto fy  = (y[i] - 1) * MultTab::multInv;
            const auto ffy = (fy - 1) * MultTab::multInv;

            // get possible LSB(Xi)
            for (const auto xi_0_8 : MultTab::getMsbProdFiber2(msb(ffy - (y[i - 2] & mask<24, 32>))))
            {
                // compute corresponding Y{i-1}
                const auto yim1 = fy - xi_0_8;

                // filter values with Y{i-2}[24,32)
                if (ffy - MultTab::multInv * xi_0_8 - (y[i - 2] & mask<24, 32>) <= maxdiff<24> &&
                    msb(yim1) == msb(y[i - 1]))
                {
                    // add Y{i-1} to the Y-list
                    y[i - 1] = yim1;

                    // set Xi value
                    x[i] = xi_0_8;

                    searchRecursive(i - 1);
                }
            }
        }
        else // the Y-list is complete
        {
            // only the X1 LSB was not set yet, so do it here
            x[1] = (y[1] - 1) * MultTab::multInv - y[0];
            if (x[1] > 0xff)
                return;

            // complete X values and derive password
            for (auto j = 5; 0 <= j; j--)
            {
                const auto xi_xor_pi = Crc32Tab::crc32inv(x[j + 1], 0);
                p[j]                 = lsb(xi_xor_pi ^ x[j]);
                x[j]                 = xi_xor_pi ^ p[j];
            }

            if (x[0] == candidateX0) // the password is successfully recovered
                (static_cast<Derived*>(this))->onSolutionFound();
        }
    }

    // set of possible Z0[16,32) values considering given character set
    std::bitset<1 << 16> z0_16_32;

    // set of possible Z{-1}[24,32) values considering given character set
    std::bitset<1 << 8> zm1_24_32;

    // cipher state (X,Y,Z)_i for index i in [0, 6] where the last state (X,Y,Z)_6 is
    // the representation of the password to recover
    std::array<std::uint32_t, 7> x{}, y{}, z{};
    std::uint32_t                candidateX0{}; // backup of candidate X value for convenience

    std::array<std::uint8_t, 6> p{}; // password last 6 bytes
};

class BruteforceRecovery : public SixCharactersRecovery<BruteforceRecovery>
{
public:
    BruteforceRecovery(const Keys& keys, const std::vector<std::uint8_t>& charset, std::vector<std::string>& solutions,
                       std::mutex& solutionsMutex, bool exhaustive, Progress& progress)
    : SixCharactersRecovery{keys, charset, charset}
    , charset{charset}
    , solutions{solutions}
    , solutionsMutex{solutionsMutex}
    , exhaustive{exhaustive}
    , progress{progress}
    {
    }

    void search(std::size_t length)
    {
        auto restart = std::string{};
        search(length, "", restart, 1);
    }

    void search(std::size_t length, const std::string& start, std::string& restart, int jobs)
    {
        prefix.clear();
        this->length = length;

        if (length <= 6)
            searchShort();
        else if (length <= 9)
            searchLongRecursive(Keys{});
        else
        {
            progress.done  = 0;
            progress.total = charset.size() * charset.size();
            searchLongParallelRecursive(Keys{}, start, restart, jobs);
        }
    }

    void onSolutionFound() const
    {
        auto password = prefix;
        password.append(p.begin(), p.end());
        password.erase(password.begin(), password.end() - length);

        const auto isInCharset =
            std::all_of(password.begin(), password.end(),
                        [this](char c)
                        { return std::binary_search(charset.begin(), charset.end(), static_cast<std::uint8_t>(c)); });

        if (!isInCharset)
        {
            progress.log(
                [&password](std::ostream& os)
                {
                    const auto flagsBefore = os.setf(std::ios::hex, std::ios::basefield);
                    const auto fillBefore  = os.fill('0');

                    os << "Password: " << password << " (as bytes:";
                    for (const auto c : password)
                        os << ' ' << std::setw(2) << int{static_cast<std::uint8_t>(c)};
                    os << ')' << std::endl;

                    os.fill(fillBefore);
                    os.flags(flagsBefore);

                    os << "Some characters are not in the expected charset. Continuing." << std::endl;
                });

            return;
        }

        {
            const auto lock = std::scoped_lock{solutionsMutex};
            solutions.push_back(password);
        }

        progress.log([&password](std::ostream& os) { os << "Password: " << password << std::endl; });

        if (!exhaustive)
            progress.state = Progress::State::EarlyExit;
    }

private:
    /// \brief Look for a password of length 6 or less
    ///
    /// \pre prefix.empty() && length <= 6
    void searchShort()
    {
        auto initial = Keys{};
        // update initial state backward so that there are exactly 6 updates between it and the target state
        for (auto i = length; i < 6; i++)
            initial.updateBackwardPlaintext(charset.front());

        SixCharactersRecovery::search(initial);
    }

    /// \brief Look for password of length 7 or more
    ///
    /// Recursively iterate on possible prefixes of length-6 characters.
    /// For each prefix, try to recover the last 6 characters with SixCharactersRecovery::search.
    ///
    /// \pre prefix.size() + 6 < length
    void searchLongRecursive(const Keys& initial)
    {
        if (prefix.size() + 7 == length) // there is only one more character to bruteforce
        {
            // check compatible Z{-1}[24, 32)
            if (!zm1_24_32[initial.getZ() >> 24])
                return;

            prefix.push_back(charset[0]);

            // precompute as much as we can about the next cipher state without knowing the password byte
            const auto x0_partial = Crc32Tab::crc32(initial.getX(), 0);
            const auto y0_partial = initial.getY() * MultTab::mult + 1;
            const auto z0_partial = Crc32Tab::crc32(initial.getZ(), 0);

            for (const auto pi : charset)
            {
                // finish to update the cipher state
                const auto x0 = x0_partial ^ Crc32Tab::crc32(0, pi);
                const auto y0 = y0_partial + MultTab::mult * lsb(x0);
                const auto z0 = z0_partial ^ Crc32Tab::crc32(0, msb(y0));

                // SixCharactersRecovery::search is inlined below for performance

                // check compatible Z0[16,32)
                if (!z0_16_32[z0 >> 16])
                    continue;

                prefix.back() = pi;

                // initialize starting X, Y and Z values
                x[0] = candidateX0 = x0;
                y[0]               = y0;
                z[0]               = z0;

                // complete Z values and derive Y[24,32) values
                y[1] = Crc32Tab::getYi_24_32(z[1], z[1 - 1]);
                z[1] = Crc32Tab::crc32(z[1 - 1], msb(y[1]));
                y[2] = Crc32Tab::getYi_24_32(z[2], z[2 - 1]);
                z[2] = Crc32Tab::crc32(z[2 - 1], msb(y[2]));
                y[3] = Crc32Tab::getYi_24_32(z[3], z[3 - 1]);
                z[3] = Crc32Tab::crc32(z[3 - 1], msb(y[3]));
                y[4] = Crc32Tab::getYi_24_32(z[4], z[4 - 1]);
                // z[4] = Crc32Tab::crc32(z[4 - 1], msb(y[4])); // this one is already known

                // recursively complete Y values and derive password
                searchRecursive(5);
            }

            prefix.pop_back();
        }
        else // bruteforce the next character and continue recursively
        {
            prefix.push_back(charset[0]);

            for (const auto pi : charset)
            {
                Keys init = initial;
                init.update(pi);

                prefix.back() = pi;

                searchLongRecursive(init);
            }

            prefix.pop_back();
        }
    }

    /// \brief Look for password of length 10 or more
    ///
    /// Recursively iterate on possible prefixes of length-6 characters.
    /// Start parallel workers looking for a password of length 9.
    ///
    /// \pre prefix.size() + 9 < length
    void searchLongParallelRecursive(const Keys& initial, const std::string& start, std::string& restart, int jobs)
    {
        const auto charsetSize = static_cast<int>(charset.size());

        auto index_start = 0;
        if (prefix.size() < start.size())
            while (index_start < charsetSize && charset[index_start] < static_cast<unsigned char>(start[prefix.size()]))
                ++index_start;

        if (prefix.size() + 1 + 9 == length) // bruteforce one character in parallel
        {
            prefix.push_back(charset[0]);

            progress.done += index_start * charsetSize;

            const auto threadCount        = std::clamp(jobs, 1, charsetSize);
            auto       threads            = std::vector<std::thread>{};
            auto       nextCandidateIndex = std::atomic<int>{index_start};
            for (auto i = 0; i < threadCount; ++i)
                threads.emplace_back(
                    [&nextCandidateIndex, charsetSize, clone = *this, initial]() mutable
                    {
                        for (auto i = nextCandidateIndex++; i < charsetSize; i = nextCandidateIndex++)
                        {
                            const auto pm4 = clone.charset[i];

                            auto init = initial;
                            init.update(pm4);

                            clone.prefix.back() = pm4;

                            clone.searchLongRecursive(init);

                            clone.progress.done += charsetSize;

                            if (clone.progress.state != Progress::State::Normal)
                                break;
                        }
                    });
            for (auto& thread : threads)
                thread.join();

            prefix.pop_back();

            if (nextCandidateIndex < charsetSize)
            {
                restart = prefix;
                restart.push_back(charset[nextCandidateIndex]);
                restart.append(length - 6 - restart.size(), charset[0]);
            }
        }
        else if (prefix.size() + 2 + 9 == length) // bruteforce two characters in parallel
        {
            index_start *= charsetSize;
            if (prefix.size() + 1 < start.size())
            {
                const auto maxIndex = std::min(charsetSize * charsetSize, index_start + charsetSize);
                while (index_start < maxIndex &&
                       charset[index_start % charsetSize] < static_cast<unsigned char>(start[prefix.size() + 1]))
                    ++index_start;
            }

            prefix.push_back(charset[0]);
            prefix.push_back(charset[0]);

            const auto reportProgress       = prefix.size() == 2;
            const auto reportProgressCoarse = prefix.size() == 3;

            if (reportProgress)
                progress.done += index_start;
            else if (reportProgressCoarse)
                progress.done += index_start / charsetSize;

            const auto threadCount        = std::clamp(jobs, 1, charsetSize * charsetSize);
            auto       threads            = std::vector<std::thread>{};
            auto       nextCandidateIndex = std::atomic<int>{index_start};
            for (auto i = 0; i < threadCount; ++i)
                threads.emplace_back(
                    [&nextCandidateIndex, charsetSize, clone = *this, initial, reportProgress,
                     reportProgressCoarse]() mutable
                    {
                        for (auto i = nextCandidateIndex++; i < charsetSize * charsetSize; i = nextCandidateIndex++)
                        {
                            const auto pm4 = clone.charset[i / charsetSize];
                            const auto pm3 = clone.charset[i % charsetSize];

                            auto init = initial;
                            init.update(pm4);
                            init.update(pm3);

                            clone.prefix[clone.prefix.size() - 2] = pm4;
                            clone.prefix[clone.prefix.size() - 1] = pm3;

                            clone.searchLongRecursive(init);

                            if (reportProgress || (reportProgressCoarse && i % charsetSize == 0))
                                clone.progress.done++;

                            if (clone.progress.state != Progress::State::Normal)
                                break;
                        }
                    });
            for (auto& thread : threads)
                thread.join();

            prefix.pop_back();
            prefix.pop_back();

            if (nextCandidateIndex < charsetSize * charsetSize)
            {
                restart = prefix;
                restart.push_back(charset[nextCandidateIndex / charsetSize]);
                restart.push_back(charset[nextCandidateIndex % charsetSize]);
                restart.append(length - 6 - restart.size(), charset[0]);
            }
        }
        else // try password prefixes recursively
        {
            prefix.push_back(charset[0]);

            const auto reportProgress = prefix.size() == 2;

            if (prefix.size() == 1)
                progress.done += index_start * charsetSize;
            else if (reportProgress)
                progress.done += index_start;

            for (auto i = index_start; i < charsetSize; i++)
            {
                const auto pi = charset[i];

                auto init = initial;
                init.update(pi);

                prefix.back() = pi;

                if (progress.state != Progress::State::Normal)
                {
                    restart = prefix;
                    restart.resize(length - 6, charset[0]);
                    break;
                }

                searchLongParallelRecursive(init, i == index_start ? start : "", restart, jobs);

                // Because the recursive call may explore only a fraction of its
                // search space, check that it was run in full before counting progress.
                if (!restart.empty())
                    break;

                if (reportProgress)
                    progress.done++;
            }

            prefix.pop_back();
        }
    }

    /// Length of the password to recover
    std::size_t length;

    /// The first characters of the password candidate, up to length-6 characters long
    std::string prefix;

    /// Set of characters to generate password candidates
    const std::vector<std::uint8_t>& charset;

    std::vector<std::string>& solutions; // shared output vector of valid passwords
    std::mutex&               solutionsMutex;
    const bool                exhaustive;
    Progress&                 progress;
};

auto recoverPassword(const Keys& keys, const std::vector<std::uint8_t>& charset, std::size_t minLength,
                     std::size_t maxLength, std::string& start, int jobs, bool exhaustive, Progress& progress)
    -> std::vector<std::string>
{
    auto solutions      = std::vector<std::string>{};
    auto solutionsMutex = std::mutex{};
    auto worker         = BruteforceRecovery{keys, charset, solutions, solutionsMutex, exhaustive, progress};

    auto       restart     = std::string{};
    const auto startLength = std::max(minLength, start.empty() ? 0 : start.size() + 6);
    for (auto length = startLength; length <= maxLength; length++)
    {
        if (progress.state != Progress::State::Normal)
            break;

        if (length <= 6)
        {
            progress.log([](std::ostream& os) { os << "length 0-6..." << std::endl; });

            // look for a password of length between 0 and 6
            for (auto l = 0; l <= 6; l++)
                worker.search(l);

            length = 6; // searching up to length 6 is done
        }
        else
        {
            progress.log([length](std::ostream& os) { os << "length " << length << "..." << std::endl; });
            worker.search(length, length == startLength ? start : "", restart, jobs);
        }
    }

    start = restart;

    return solutions;
}
