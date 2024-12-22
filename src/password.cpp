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
    void setTarget(const Keys& target, const std::vector<std::uint8_t>& charset5)
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

            const auto y3_ignoring_lsb_x4 = (y[4] - 1) * MultTab::multInv;
            const auto msb_y3_min         = msb(y3_ignoring_lsb_x4 - 255);
            const auto msb_y3_max         = msb(y3_ignoring_lsb_x4 - 0);

            z[2] = Crc32Tab::crc32inv(z[3], msb_y3_min);
            z[1] = Crc32Tab::crc32inv(z[2], 0);
            z[0] = Crc32Tab::crc32inv(z[1], 0);

            z0_16_32.set(z[0] >> 16);
            zm1_24_32.set(Crc32Tab::crc32inv(z[0], 0) >> 24);

            if (msb_y3_max != msb_y3_min)
            {
                z[2] = Crc32Tab::crc32inv(z[3], msb_y3_max);
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
        setTarget(keys, charset);
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
            initial.updateBackwardPlaintext('\0');

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

                            if (reportProgress || (reportProgressCoarse && i % charsetSize == charsetSize - 1))
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

        if (mask.size() < 6)
        {
            // update target state forward so that there are exactly 6 updates between it and the initial state
            auto pastTarget = target;
            for (auto i = mask.size(); i < 6; ++i)
                pastTarget.update('\0');
            setTarget(pastTarget, {'\0'});
            SixCharactersRecovery::search(Keys{});
            return;
        }
        else if (mask.size() == 6)
        {
            setTarget(target, mask[5]);
            SixCharactersRecovery::search(Keys{});
            return;
        }
        else // 7 or more characters
        {
            if (suffixSize == 0)
                setTarget(target, mask[factorIndex + 5]);

            if (parallelDepth == -1)
                searchLongRecursive(Keys{}, target);
            else
            {
                if (progressDepth)
                {
                    auto product = 1;
                    for (auto i = 0u; i < progressDepth; ++i)
                        product *= getCharsetAtDepth(i).size();

                    progress.done  = 0;
                    progress.total = product;
                }
                searchLongParallelRecursive(Keys{}, target, start, restart, jobs);
            }
        }
    }

    void onSolutionFound() const
    {
        auto password = std::string{};
        password.append(decisions.begin() + suffixSize, decisions.end());
        password.append(p.begin(), p.end());
        password.append(decisions.rbegin() + factorIndex, decisions.rend());
        password.resize(mask.size());

        const auto isInSearchSpace =
            std::all_of(password.begin(), password.end(),
                        [this, i = 0](char c) mutable
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
                        os << ' ' << std::setw(2) << int{static_cast<std::uint8_t>(c)};
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
    /// \brief Look for password of length 7 or more
    ///
    /// Recursively iterate on possible reversed suffixes and prefixes, for a total of mask.size()-6 characters.
    /// For each case, try to recover the last 6 characters with SixCharactersRecovery::search.
    ///
    /// \pre decisions.size() + 6 < mask.size()
    void searchLongRecursive(const Keys& afterPrefix, const Keys& beforeSuffix)
    {
        const auto depth = decisions.size();

        if (depth + 7 == mask.size()) // there is only one more character to bruteforce
        {
            if (depth < suffixSize) // bruteforce the last remaining suffix character
            {
                decisions.emplace_back();

                for (const auto pi : getCharsetAtDepth(depth))
                {
                    auto beforeSuffix2 = beforeSuffix;
                    beforeSuffix2.updateBackwardPlaintext(pi);
                    setTarget(beforeSuffix2, mask[factorIndex + 5]);

                    decisions.back() = pi;

                    SixCharactersRecovery::search(afterPrefix);
                }

                decisions.pop_back();
            }
            else // bruteforce the last remaining prefix character
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
        }
        else // bruteforce the next character and continue recursively
        {
            decisions.emplace_back();

            if (depth < suffixSize) // bruteforce the next suffix character
            {
                for (const auto pi : getCharsetAtDepth(depth))
                {
                    auto beforeSuffix2 = beforeSuffix;
                    beforeSuffix2.updateBackwardPlaintext(pi);
                    if (depth + 1 == suffixSize)
                        setTarget(beforeSuffix2, mask[factorIndex + 5]);

                    decisions.back() = pi;

                    searchLongRecursive(afterPrefix, beforeSuffix2);
                }
            }
            else // bruteforce the next prefix character
            {
                for (const auto pi : getCharsetAtDepth(depth))
                {
                    auto afterPrefix2 = afterPrefix;
                    afterPrefix2.update(pi);

                    decisions.back() = pi;

                    searchLongRecursive(afterPrefix2, beforeSuffix);
                }
            }

            decisions.pop_back();
        }
    }

    /// Look for password recursively up to depth parallelDepth.
    /// Then parallelize the next two decisions and continue exploration with searchLongRecursive.
    void searchLongParallelRecursive(const Keys& afterPrefix, const Keys& beforeSuffix, const std::string& start,
                                     std::string& restart, int jobs)
    {
        const auto  depth   = decisions.size();
        const auto& charset = getCharsetAtDepth(depth);

        auto index_start = 0;
        if (decisions.size() < start.size())
            while (index_start < static_cast<int>(charset.size()) &&
                   charset[index_start] < static_cast<unsigned char>(start[depth]))
                ++index_start;

        if (static_cast<int>(depth) == parallelDepth) // parallelize the next two decisions
        {
            const auto& nextCharset       = getCharsetAtDepth(depth + 1);
            const auto  parallelSpaceSize = static_cast<int>(charset.size() * nextCharset.size());

            index_start *= nextCharset.size();
            if (decisions.size() + 1 < start.size())
            {
                const auto maxIndex = std::min(parallelSpaceSize, index_start + static_cast<int>(nextCharset.size()));
                while (index_start < maxIndex && nextCharset[index_start % nextCharset.size()] <
                                                     static_cast<unsigned char>(start[decisions.size() + 1]))
                    ++index_start;
            }

            decisions.resize(depth + 2);

            const auto reportProgress       = decisions.size() == progressDepth;
            const auto reportProgressCoarse = decisions.size() == progressDepth + 1;

            if (reportProgress)
                progress.done += index_start;
            else if (reportProgressCoarse)
                progress.done += index_start / nextCharset.size();

            const auto threadCount        = std::clamp(jobs, 1, parallelSpaceSize);
            auto       threads            = std::vector<std::thread>{};
            auto       nextCandidateIndex = std::atomic<int>{index_start};
            for (auto i = 0; i < threadCount; ++i)
                threads.emplace_back(
                    [beforeSuffix, afterPrefix, &nextCandidateIndex, &charset, &nextCharset, depth, parallelSpaceSize,
                     clone = *this, reportProgress, reportProgressCoarse]() mutable
                    {
                        for (auto i = nextCandidateIndex++; i < parallelSpaceSize; i = nextCandidateIndex++)
                        {
                            const auto firstChoice  = charset[i / nextCharset.size()];
                            const auto secondChoice = nextCharset[i % nextCharset.size()];

                            auto afterPrefix2  = afterPrefix;
                            auto beforeSuffix2 = beforeSuffix;

                            if (depth < clone.suffixSize)
                            {
                                beforeSuffix2.updateBackwardPlaintext(firstChoice);
                                if (depth + 1 == clone.suffixSize)
                                    clone.setTarget(beforeSuffix2, clone.mask[clone.factorIndex + 5]);
                            }
                            else
                                afterPrefix2.update(firstChoice);

                            if (depth + 1 < clone.suffixSize)
                            {
                                beforeSuffix2.updateBackwardPlaintext(secondChoice);
                                if (depth + 2 == clone.suffixSize)
                                    clone.setTarget(beforeSuffix2, clone.mask[clone.factorIndex + 5]);
                            }
                            else
                                afterPrefix2.update(secondChoice);

                            clone.decisions[depth]     = firstChoice;
                            clone.decisions[depth + 1] = secondChoice;

                            clone.searchLongRecursive(afterPrefix2, beforeSuffix2);

                            if (reportProgress ||
                                (reportProgressCoarse && i % nextCharset.size() == nextCharset.size() - 1))
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
                restart.push_back(charset[nextCandidateIndex / nextCharset.size()]);
                restart.push_back(nextCharset[nextCandidateIndex % nextCharset.size()]);
                while (restart.size() < mask.size() - 6)
                    restart.push_back(getCharsetAtDepth(restart.size())[0]);
            }
        }
        else // take next decisions recursively
        {
            decisions.emplace_back();

            const auto reportProgress = depth + 1 == progressDepth;

            if (depth + 1 <= progressDepth)
            {
                auto subSearchSize = 1;
                for (auto i = depth + 1; i < progressDepth; ++i)
                    subSearchSize *= getCharsetAtDepth(i).size();
                progress.done += index_start * subSearchSize;
            }

            for (auto i = index_start; i < static_cast<int>(charset.size()); i++)
            {
                const auto pi = charset[i];

                auto afterPrefix2  = afterPrefix;
                auto beforeSuffix2 = beforeSuffix;
                if (depth < suffixSize)
                {
                    beforeSuffix2.updateBackwardPlaintext(pi);
                    if (depth + 1 == suffixSize)
                        setTarget(beforeSuffix2, mask[factorIndex + 5]);
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

    /// Internal representation of the password to recover
    const Keys target;

    /// Sequence of charsets to generate password candidates
    const std::vector<std::vector<std::uint8_t>>& mask;

    /// \brief factor start index
    ///
    /// The mask is split in three parts: prefix, 6 characters factor, suffix.
    /// We want to choose the factor start index f that minimizes the password search computational cost.
    /// The search cost is estimated with the following linear combination:
    ///     cost(f) = 0.70 * a(f) + 0.24 * b(f) + 0.06 * c(f)
    /// where:
    ///     a(f) = s(f) * mask[f + 5].size()                                 (setTarget iterations)
    ///     b(f) = s(f) * p(f) * (1.0 - zm1Ratio(f)) / mask[f - 1].size()    (early exits on zm1_24_32 mismatch)
    ///     c(f) = s(f) * p(f) * zm1Ratio(f)                                 (SixCharactersRecovery::search calls)
    ///     s(f) = product of mask[i].size() for i in [f + 6 .. mask.size())
    ///     p(f) = product of mask[i].size() for i in [0 .. f)
    ///     zm1Ratio(f) = mask[f + 5].size() / 256.0
    /// Weights 0.70, 0.24, 0.06 have been determined by experiment (time measurement and linear regression).
    const std::size_t factorIndex = [this]
    {
        if (mask.size() < 7)
            return std::size_t{0};

        const auto cost = [this](std::size_t f) -> double
        {
            auto p = 1.0;
            for (auto i = 0u; i < f; ++i)
                p *= mask[i].size();

            auto s = 1.0;
            for (auto i = f + 6; i < mask.size(); ++i)
                s *= mask[i].size();

            const auto m5       = static_cast<double>(mask[f + 5].size());
            const auto mm1      = f ? static_cast<double>(mask[f - 1].size()) : 1.0;
            const auto zm1Ratio = f ? m5 / 256.0 : 1.0;

            const auto a = s * m5;
            const auto b = s * p * (1.0 - zm1Ratio) / mm1;
            const auto c = s * p * zm1Ratio;

            return 0.70 * a + 0.24 * b + 0.06 * c;
        };

        auto best = std::pair{std::size_t{0}, cost(0)};
        for (auto f = std::size_t{1}; f + 6 <= mask.size(); ++f)
            if (const auto c = cost(f); c <= best.second)
                best = {f, c};

        return best.first;
    }();

    const std::size_t suffixSize = mask.size() < 7 ? 0 : mask.size() - factorIndex - 6;

    /// \brief Get the charset for the given depth of recursive exploration
    ///
    /// Mask charsets are explored recursively starting from the suffix charsets in reverse order,
    /// then followed by the prefix charsets.
    const std::vector<std::uint8_t>& getCharsetAtDepth(std::size_t i)
    {
        if (i < suffixSize)
            return mask[mask.size() - 1 - i];
        else
            return mask[i - suffixSize];
    }

    /// \brief Depth of the recursive exploration at which parallel workers are started
    ///
    /// -1 means the recursive exploration is not parallelized.
    const int parallelDepth = [this]
    {
        if (mask.size() < 7)
            return -1;

        // Find deepest recursion level with remaining search space of given size or more
        const auto getDepthForSize = [this](std::uint64_t size) -> std::size_t
        {
            auto product = std::uint64_t{1};
            for (auto i = mask.size() - 6; 0 < i; --i)
            {
                product *= getCharsetAtDepth(i - 1).size();
                if (size <= product)
                    return i - 1;
            }
            return 0;
        };

        const auto atomicWorkDepth = getDepthForSize(1ul << 16);

        // not deep enough to warrant parallelization
        if (atomicWorkDepth < 2)
            return -1;

        // Parallelizing earlier than this depth might make the program slow to stop
        // upon SIGINT or upon finding a solution.
        const auto shallowestParallelDepth = getDepthForSize(1ul << 32);

        // Find two consecutive characters to be guessed in parallel, maximizing the work items count.
        auto best = std::pair{-1, std::size_t{1}};
        for (auto i = shallowestParallelDepth; i + 1 < atomicWorkDepth; ++i)
            if (const auto product = getCharsetAtDepth(i).size() * getCharsetAtDepth(i + 1).size();
                best.second < product)
                best = {i, product};

        return best.first;
    }();

    /// \brief Depth of the recursive exploration at which progress is counted
    ///
    /// 0 means progress is not reported.
    const std::size_t progressDepth = [this]
    {
        // Progress is not reported when the recursive exploration is not paralellized, because it is fast.
        if (parallelDepth < 0)
            return 0;

        // Find first recursion level with 100 or more iterations
        auto product = 1;
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

auto recoverPassword(const Keys& keys, const std::vector<std::vector<std::uint8_t>>& mask, std::string& start, int jobs,
                     bool exhaustive, Progress& progress) -> std::vector<std::string>
{
    auto solutions      = std::vector<std::string>{};
    auto solutionsMutex = std::mutex{};
    auto worker         = MaskRecovery{keys, mask, solutions, solutionsMutex, exhaustive, progress};

    auto restart = std::string{};
    worker.search(start, restart, jobs);

    start = restart;

    return solutions;
}
