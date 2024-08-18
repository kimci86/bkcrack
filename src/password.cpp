#include "password.hpp"

#include "Crc32Tab.hpp"
#include "MultTab.hpp"
#include "log.hpp"

#include <algorithm>
#include <atomic>
#include <bitset>
#include <iomanip>
#include <mutex>
#include <numeric>
#include <thread>

template <typename Derived /* must implement onSolutionFound() method */>
class SixCharactersRecovery
{
public:
    void setTarget(const Keys& target, const std::vector<std::uint8_t>& charset4,
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
        z0_16_32.reset();
        zm1_24_32.reset();
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
    : charset{charset}
    , solutions{solutions}
    , solutionsMutex{solutionsMutex}
    , exhaustive{exhaustive}
    , progress{progress}
    {
        setTarget(keys, charset, charset);
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
                        os << ' ' << std::setw(2) << static_cast<int>(c);
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

class MaskRecovery : public SixCharactersRecovery<MaskRecovery>
{
public:
    MaskRecovery(const Keys& keys, const std::vector<std::vector<std::uint8_t>>& mask,
                 std::vector<std::string>& solutions, std::mutex& solutionsMutex, bool exhaustive, Progress& progress)
    : target{keys}
    , mask{mask}
    , solutions{solutions}
    , solutionsMutex{solutionsMutex}
    , exhaustive{exhaustive}
    , progress{progress}
    {
    }

    void search(const std::string& start, std::string& restart, int jobs)
    {
        decisions.clear();

        if (getSuffixSize() == 0)
            setTarget(target, mask[factorIndex + 4], mask[factorIndex + 5]);

        if (parallelDepth == -1)
            searchLongRecursive(Keys{}, target);
        else
        {
            if (progressDepth)
            {
                auto product = int{1};
                for (auto i = 0; i < progressDepth; ++i)
                    product *= getCharsetAtDepth(i).size();

                progress.done  = 0;
                progress.total = product;
            }
            searchLongParallelRecursive(Keys{}, target, start, restart, jobs);
        }
    }

    void onSolutionFound()
    {
        auto password = std::string{};
        password.append(decisions.begin() + getSuffixSize(), decisions.end());
        password.append(p.begin(), p.end());
        password.append(decisions.rbegin() + factorIndex, decisions.rend());

        const auto isInSearchSpace =
            std::all_of(p.begin(), p.end(),
                        [this, i = factorIndex](char c) mutable
                        {
                            const auto& charset = mask[i++];
                            return std::binary_search(charset.begin(), charset.end(), static_cast<std::uint8_t>(c));
                        });

        if (!isInSearchSpace)
        {
            progress.log(
                [&password](std::ostream& os)
                {
                    const auto flagsBefore = os.setf(std::ios::hex, std::ios::basefield);
                    const auto fillBefore  = os.fill('0');

                    os << "Password: " << password << " (as bytes:";
                    for (const auto c : password)
                        os << ' ' << std::setw(2) << static_cast<int>(c);
                    os << ')' << std::endl;

                    os.fill(fillBefore);
                    os.flags(flagsBefore);

                    os << "Some characters do not match the given mask. Continuing." << std::endl;
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
    void searchLongRecursive(const Keys& afterPrefix, const Keys& beforeSuffix)
    {
        const auto depth = decisions.size();

        if (depth + 7 == mask.size()) // there is only one more character to bruteforce
        {
            if (factorIndex)
            {
                // check compatible Z{-1}[24, 32)
                if (!zm1_24_32[afterPrefix.getZ() >> 24])
                    return;

                decisions.emplace_back();

                // precompute as much as we can about the next cipher state without knowing the password byte
                const auto x0_partial = Crc32Tab::crc32(afterPrefix.getX(), 0);
                const auto y0_partial = afterPrefix.getY() * MultTab::mult + 1;
                const auto z0_partial = Crc32Tab::crc32(afterPrefix.getZ(), 0);

                for (const auto pi : getCharsetAtDepth(depth))
                {
                    // finish to update the cipher state
                    const auto x0 = x0_partial ^ Crc32Tab::crc32(0, pi);
                    const auto y0 = y0_partial + MultTab::mult * lsb(x0);
                    const auto z0 = z0_partial ^ Crc32Tab::crc32(0, msb(y0));

                    // SixCharactersRecovery::search is inlined below for performance

                    // check compatible Z0[16,32)
                    if (!z0_16_32[z0 >> 16])
                        continue;

                    decisions.back() = pi;

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

                decisions.pop_back();
            }
            else
            {
                decisions.emplace_back();

                for (const auto pi : getCharsetAtDepth(depth))
                {
                    auto beforeSuffix2 = beforeSuffix;
                    beforeSuffix2.updateBackwardPlaintext(pi);
                    if (depth + 1 == getSuffixSize())
                        setTarget(beforeSuffix2, mask[factorIndex + 4], mask[factorIndex + 5]);

                    decisions.back() = pi;

                    SixCharactersRecovery::search(afterPrefix);
                }

                decisions.pop_back();
            }
        }
        else // bruteforce the next character and continue recursively
        {
            decisions.emplace_back();

            for (const auto pi : getCharsetAtDepth(depth))
            {
                auto afterPrefix2  = afterPrefix;
                auto beforeSuffix2 = beforeSuffix;

                if (depth < getSuffixSize())
                {
                    beforeSuffix2.updateBackwardPlaintext(pi);
                    if (depth + 1 == getSuffixSize())
                        setTarget(beforeSuffix2, mask[factorIndex + 4], mask[factorIndex + 5]);
                }
                else
                    afterPrefix2.update(pi);

                decisions.back() = pi;

                searchLongRecursive(afterPrefix2, beforeSuffix2);
            }

            decisions.pop_back();
        }
    }

    void searchLongParallelRecursive(const Keys& afterPrefix, const Keys& beforeSuffix, const std::string& start,
                                     std::string& restart, int jobs)
    {
        const auto  depth   = decisions.size();
        const auto& charset = getCharsetAtDepth(depth);

        auto index_start = 0;
        if (decisions.size() < start.size())
            while (index_start < static_cast<int>(charset.size()) &&
                   charset[index_start] < static_cast<unsigned char>(start[decisions.size()]))
                ++index_start;

        if (static_cast<int>(depth) == parallelDepth) // parallelize the next two decisions
        {
            const auto& nextCharset       = getCharsetAtDepth(depth + 1);
            const auto  parallelSpaceSize = static_cast<int>(charset.size() * nextCharset.size());

            index_start *= charset.size();
            if (decisions.size() + 1 < start.size())
            {
                const auto maxIndex = std::min(parallelSpaceSize, index_start + static_cast<int>(nextCharset.size()));
                while (index_start < static_cast<int>(maxIndex) &&
                       nextCharset[index_start % charset.size()] <
                           static_cast<unsigned char>(start[decisions.size() + 1]))
                    ++index_start;
            }

            decisions.resize(depth + 2);

            const auto reportProgress       = static_cast<int>(decisions.size()) == progressDepth;
            const auto reportProgressCoarse = static_cast<int>(decisions.size()) == progressDepth + 1;

            const auto& mask4 = mask[factorIndex + 4];
            const auto& mask5 = mask[factorIndex + 5];

            const auto threadCount        = std::clamp(jobs, 1, parallelSpaceSize);
            auto       threads            = std::vector<std::thread>{};
            auto       nextCandidateIndex = std::atomic<int>{index_start};
            for (auto i = 0; i < threadCount; ++i)
                threads.emplace_back(
                    [beforeSuffix, afterPrefix, &nextCandidateIndex, &charset, &nextCharset, &mask4, &mask5, depth,
                     suffixSize = getSuffixSize(), parallelSpaceSize, clone = *this, reportProgress,
                     reportProgressCoarse]() mutable
                    {
                        for (auto i = nextCandidateIndex++; i < parallelSpaceSize; i = nextCandidateIndex++)
                        {
                            const auto firstChoice  = charset[i / nextCharset.size()];
                            const auto secondChoice = nextCharset[i % nextCharset.size()];

                            clone.decisions[depth]     = firstChoice;
                            clone.decisions[depth + 1] = secondChoice;

                            auto afterPrefix2  = afterPrefix;
                            auto beforeSuffix2 = beforeSuffix;

                            if (depth < suffixSize)
                            {
                                beforeSuffix2.updateBackwardPlaintext(firstChoice);
                                if (depth + 1 == suffixSize)
                                    clone.setTarget(beforeSuffix2, mask4, mask5);
                            }
                            else
                                afterPrefix2.update(firstChoice);

                            if (depth + 1 < suffixSize)
                            {
                                beforeSuffix2.updateBackwardPlaintext(secondChoice);
                                if (depth + 2 == suffixSize)
                                    clone.setTarget(beforeSuffix2, mask4, mask5);
                            }
                            else
                                afterPrefix2.update(secondChoice);

                            clone.searchLongRecursive(afterPrefix2, beforeSuffix2);

                            if (reportProgress || (reportProgressCoarse && i % charset.size() == 0))
                                clone.progress.done++;

                            if (clone.progress.state != Progress::State::Normal)
                                break;
                        }
                    });
            for (auto& thread : threads)
                thread.join();

            decisions.resize(depth);

            if (nextCandidateIndex < parallelSpaceSize)
            {
                restart = std::string{decisions.begin(), decisions.end()};
                restart.push_back(charset[nextCandidateIndex / charset.size()]);
                restart.push_back(charset[nextCandidateIndex % charset.size()]);
                while (restart.size() < mask.size() - 6)
                    restart.push_back(getCharsetAtDepth(restart.size())[0]);
            }
        }
        else // take next decisions recursively
        {
            decisions.emplace_back();

            const auto reportProgress = static_cast<int>(depth + 1) == progressDepth;

            if (static_cast<int>(depth + 1) < progressDepth)
            {
                auto subSearchSize = 1;
                for (auto i = static_cast<int>(depth) + 1; i < progressDepth; ++i)
                    subSearchSize *= getCharsetAtDepth(i).size();
                progress.done += index_start * subSearchSize;
            }
            if (reportProgress)
                progress.done += index_start;

            for (auto i = index_start; i < static_cast<int>(charset.size()); i++)
            {
                const auto pi = charset[i];

                auto afterPrefix2  = afterPrefix;
                auto beforeSuffix2 = beforeSuffix;
                if (depth < getSuffixSize())
                {
                    beforeSuffix2.updateBackwardPlaintext(pi);
                    if (depth + 1 == getSuffixSize())
                        setTarget(beforeSuffix2, mask[factorIndex + 4], mask[factorIndex + 5]);
                }
                else
                    afterPrefix2.update(pi);

                decisions.back() = pi;

                if (progress.state != Progress::State::Normal)
                {
                    restart = std::string{decisions.begin(), decisions.end()};
                    while (restart.size() < mask.size() - 6)
                        restart.push_back(getCharsetAtDepth(restart.size())[0]);
                    break;
                }

                searchLongParallelRecursive(afterPrefix2, beforeSuffix2, i == index_start ? start : "", restart, jobs);

                // Because the recursive call may explore only a fraction of its
                // search space, check that it was run in full before counting progress.
                if (!restart.empty())
                    break;

                if (reportProgress)
                    progress.done++;
            }

            decisions.pop_back();
        }
    }

    const Keys target;

    const std::vector<std::vector<std::uint8_t>>& mask;

    const std::size_t factorIndex = [this]
    {
        // Split mask in three parts (prefix, 6 characters factor, suffix) that minimizes the search space.
        // The search space size being the size of suffix space and prefix space combined,
        // we minimize search space size by maximizing the factor space size.

        auto product = std::accumulate(mask.begin(), mask.begin() + 6, std::uint64_t{1},
                                       [](std::uint64_t acc, const std::vector<std::uint8_t>& charset)
                                       { return acc * charset.size(); });
        auto best    = std::pair{product, std::size_t{0}};
        for (auto i = std::size_t{1}; i + 6 <= mask.size(); ++i)
        {
            product = product / mask[i - 1].size() * mask[i + 5].size();
            best    = std::max(best, std::pair{product, i});
        }

        return best.second;
    }();

    auto getSuffixSize() const -> std::size_t
    {
        return mask.size() - factorIndex - 6;
    }

    const std::vector<std::uint8_t>& getCharsetAtDepth(int i)
    {
        if (static_cast<std::size_t>(i) < getSuffixSize())
            return mask[mask.size() - 1 - i];
        else
            return mask[i - getSuffixSize()];
    }

    const int atomicWorkDepth = [this]
    {
        auto product = int{1};
        for (auto i = mask.size() - 6; 0 < i; --i)
        {
            product *= getCharsetAtDepth(i - 1).size();
            if (1 << 16 <= product)
                return static_cast<int>(i) - 1;
        }
        return 0;
    }();

    const int parallelDepth = [this]
    {
        if (atomicWorkDepth < 2)
            return -1;

        auto product = static_cast<int>(getCharsetAtDepth(0).size() * getCharsetAtDepth(1).size());
        auto best    = std::pair{product, std::size_t{0}};
        for (auto i = std::size_t{1}; i + 1 != static_cast<std::size_t>(atomicWorkDepth); ++i)
        {
            product = product / getCharsetAtDepth(i - 1).size() * getCharsetAtDepth(i + 1).size();
            best    = std::max(best, std::pair{product, i});
        }

        return (1 < best.first) ? static_cast<int>(best.second) : -1;
    }();

    const int progressDepth = [this]
    {
        if (parallelDepth < 0)
            return 0;

        auto product = int{1};
        for (auto i = 0; i < parallelDepth + 2; ++i)
        {
            product *= getCharsetAtDepth(i).size();
            if (100 <= product)
                return i + 1;
        }
        return 0;
    }();

    std::vector<std::uint8_t> decisions{}; // sequence of choices to build reversed(suffix) + prefix

    std::vector<std::string>& solutions; // shared output vector of valid passwords
    std::mutex&               solutionsMutex;
    const bool                exhaustive;
    Progress&                 progress;
};

auto recoverPassword(const Keys& keys, const std::vector<std::vector<std::uint8_t>>& mask,
                     [[maybe_unused]] std::string& start, int jobs, bool exhaustive, Progress& progress)
    -> std::vector<std::string>
{
    if (mask.size() <= 6)
    {
        progress.log([](std::ostream& os) { os << "mask is too short !" << std::endl; });
        return {};
    }

    auto solutions      = std::vector<std::string>{};
    auto solutionsMutex = std::mutex{};
    auto restart        = std::string{};
    auto worker         = MaskRecovery{keys, mask, solutions, solutionsMutex, exhaustive, progress};

    worker.search(start, restart, jobs);

    start = restart;

    return solutions;
}
