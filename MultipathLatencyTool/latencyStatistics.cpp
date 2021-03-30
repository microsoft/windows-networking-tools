#include "latencyStatistics.h"

#include <algorithm>
#include <functional>
#include <iostream>
#include <limits>
#include <numeric>
#include <ranges>
#include <vector>

namespace multipath {

constexpr long long ConvertHundredNanosToMillis(long long hundredNs) noexcept
{
    return static_cast<long long>(hundredNs / 10000LL);
}


template <std::ranges::range R, class T, class F>
[[nodiscard]] constexpr T accumulate(R&& range, T val, F reduceOp)
{
    return std::accumulate(std::begin(range), std::end(range), val, reduceOp);
}

template <std::ranges::range R, class T>
[[nodiscard]] constexpr T accumulate(R&& range, T val)
{
    return std::accumulate(std::begin(range), std::end(range), val);
}


template <std::ranges::range R>
auto to_vector(R&& r, size_t sizeHint = 0)
{
    std::vector<std::ranges::range_value_t<R>> v;

    // if we can get a size, reserve that much
    if (sizeHint != 0)
    {
        v.reserve(sizeHint);
    }

    // push all the elements
    for (auto&& e : r)
    {
        v.push_back(static_cast<decltype(e)&&>(e));
    }

    return v;
}

void PrintLatencyStatistics(std::span<const LatencyData> data)
{
    using namespace std::views;

    // Lambdas for selecting, filtering and transforming data
    auto selectPrimary = [](const LatencyData& stat) {
        return std::make_pair(stat.m_primarySendTimestamp, stat.m_primaryReceiveTimestamp);
    };
    auto selectSecondary = [](const LatencyData& stat) {
        return std::make_pair(stat.m_secondarySendTimestamp, stat.m_secondaryReceiveTimestamp);
    };
    auto selectEffective = [](const LatencyData& stat) {
        auto effectiveSend = -1LL;
        if (stat.m_primarySendTimestamp >= 0 && stat.m_secondarySendTimestamp >= 0)
        {
            effectiveSend = std::min(stat.m_primarySendTimestamp, stat.m_secondarySendTimestamp);
        }
        else
        {
            effectiveSend = std::max(stat.m_primarySendTimestamp, stat.m_secondarySendTimestamp);
        }

        auto effectiveReceive = -1LL;
        if (stat.m_primaryReceiveTimestamp >= 0 && stat.m_secondaryReceiveTimestamp >= 0)
        {
            effectiveReceive = std::min(stat.m_primaryReceiveTimestamp, stat.m_secondaryReceiveTimestamp);
        }
        else
        {
            effectiveReceive = std::max(stat.m_primaryReceiveTimestamp, stat.m_secondaryReceiveTimestamp);
        }
        return std::make_pair(effectiveSend, effectiveReceive);
    };

    auto received = [](const auto& timestamps) { return timestamps.second >= 0; };
    auto receivedOnOneInterface = [](const LatencyData& stat) {
        return stat.m_primaryReceiveTimestamp >= 0 || stat.m_secondaryReceiveTimestamp >= 0;
    };
    auto receivedFirstOnSecondary = [](const auto& stat) {
        return stat.m_secondaryReceiveTimestamp >= 0 &&
               (stat.m_primaryReceiveTimestamp < 0 || stat.m_secondaryReceiveTimestamp < stat.m_primaryReceiveTimestamp);
    };

    auto latency = [](const auto& timestamps) { return timestamps.second - timestamps.first; };

    auto sum = [](auto& data) { return accumulate(data, 0LL); };
    auto average = [](auto& data) { return data.size() > 0 ? accumulate(data, 0LL) / data.size() : 0LL; };
    auto percent = [](auto a, auto b) { return b > 0 ? a * 100 / b : 0; };
    auto median = [](const auto& data) { return data.size() > 0 ? data[data.size() / 2] : 0; };

    auto variance = [](auto& data, long long average) {
        if (data.size() == 0)
        {
            return 0LL;
        }

        long long r = 0LL;
        for (const auto& d: data)
        {
            r += d * d;
        }
        return r / static_cast<long long>(data.size()) - average * average;
    };

    // Compute latencies on primary, secondary or both simultaneously
    auto primaryLatencies = to_vector(data | transform(selectPrimary) | filter(received) | transform(latency), data.size());
    auto secondaryLatencies = to_vector(data | transform(selectSecondary) | filter(received) | transform(latency), data.size());
    auto effectiveLatencies = to_vector(data | transform(selectEffective) | filter(received) | transform(latency), data.size());

    const long long primarySentFrames =
        std::ranges::count_if(data, [](const auto& stat) { return stat.m_primarySendTimestamp >= 0; });
    const long long secondarySentFrames =
        std::ranges::count_if(data, [](const auto& stat) { return stat.m_secondarySendTimestamp >= 0; });
    const long long aggregatedSentFrames = std::ranges::count_if(
        data, [](const auto& stat) { return stat.m_primarySendTimestamp >= 0 || stat.m_secondarySendTimestamp >= 0; });
    const long long receivedOnSecondaryFirst = std::ranges::count_if(data, receivedFirstOnSecondary);

    const long long primaryReceivedFrames = primaryLatencies.size();
    const long long secondaryReceivedFrames = secondaryLatencies.size();
    const long long aggregatedReceivedFrames = effectiveLatencies.size();

    const long long primaryLostFrames = primarySentFrames - primaryReceivedFrames;
    const long long secondaryLostFrames = secondarySentFrames - secondaryReceivedFrames;
    const long long aggregatedLostFrames = aggregatedSentFrames - aggregatedReceivedFrames;

    const long long sumPrimaryLatencies = sum(primaryLatencies);
    const long long sumEffectiveLatencies = sum(effectiveLatencies);

    // Effect of the secondary interface
    std::cout << '\n';
    std::cout << "The secondary interface prevented " << primaryLostFrames - aggregatedLostFrames << "lost frames\n";
    std::cout << "The secondary interface saved " << ConvertHundredNanosToMillis(sumPrimaryLatencies - sumEffectiveLatencies)
              << "ms (" << percent(sumPrimaryLatencies - sumEffectiveLatencies, sumPrimaryLatencies) << "%)\n";
    std::cout << receivedOnSecondaryFirst << " frames were received first on the secondary interface "
              << " (" << percent(receivedOnSecondaryFirst, aggregatedReceivedFrames) << "%)\n";

    std::cout << '\n';
    std::cout << "Sent frames on primary interface: " << primarySentFrames << '\n';
    std::cout << "Sent frames on secondary interface: " << secondarySentFrames << '\n';

    std::cout << '\n';
    std::cout << "Received frames on primary interface: " << primaryReceivedFrames << " ("
              << percent(primaryReceivedFrames, primarySentFrames) << "%)\n";
    std::cout << "Received frames on secondary interface: " << secondaryReceivedFrames << " ("
              << percent(secondaryReceivedFrames, secondarySentFrames) << "%)\n";

    std::cout << '\n';
    std::cout << "Lost frames on primary interface: " << primaryLostFrames << " ("
              << percent(primaryLostFrames, primarySentFrames) << "%)\n";
    std::cout << "Lost frames on secondary interface: " << secondaryLostFrames << " ("
              << percent(secondaryLostFrames, secondarySentFrames) << "%)\n";
    std::cout << "Lost frames on both interface simultaneously: " << aggregatedLostFrames << " ("
              << percent(aggregatedLostFrames, aggregatedSentFrames) << "%)\n";

    // Average latency
    const auto primaryAverageLatency = average(primaryLatencies);
    const auto secondaryAverageLatency = average(secondaryLatencies);
    const auto effectiveAverageLatency = average(effectiveLatencies);

    std::cout << '\n';
    std::cout << "Average latency on primary interface: " << ConvertHundredNanosToMillis(primaryAverageLatency) << "ms\n";
    std::cout << "Average latency on secondary interface: " << ConvertHundredNanosToMillis(secondaryAverageLatency) << "ms\n";
    std::cout << "Average effective latency on combined interface: " << ConvertHundredNanosToMillis(effectiveAverageLatency)
              << "ms (" << percent(primaryAverageLatency - effectiveAverageLatency, primaryAverageLatency)
              << "% improvement over primary) \n";

    // Jitter / Variance
    const auto primaryVariance = variance(primaryLatencies, primaryAverageLatency);
    const auto secondaryVariance = variance(secondaryLatencies, secondaryAverageLatency);
    const auto effectiveVariance = variance(effectiveLatencies, effectiveAverageLatency);
    std::cout << '\n';
    std::cout << "Jitter (variance) on primary interface: " << ConvertHundredNanosToMillis(ConvertHundredNanosToMillis(primaryVariance)) << "ms^2\n";
    std::cout << "Jitter (variance) on secondary interface: " << ConvertHundredNanosToMillis(ConvertHundredNanosToMillis(secondaryVariance)) << "ms^2\n";
    std::cout << "Jitter (variance) on combined interfaces: " << ConvertHundredNanosToMillis(ConvertHundredNanosToMillis(effectiveVariance)) << "ms^2\n";

    // Median latency
    std::ranges::sort(primaryLatencies);
    const auto primaryMedianLatency = median(primaryLatencies);
    std::ranges::sort(secondaryLatencies);
    const auto secondaryMedianLatency = median(secondaryLatencies);
    std::ranges::sort(effectiveLatencies);
    const auto effectiveMedianLatency = median(effectiveLatencies);

    std::cout << '\n';
    std::cout << "Median latency on primary interface: " << ConvertHundredNanosToMillis(primaryMedianLatency) << "ms\n";
    std::cout << "Median latency on secondary interface: " << ConvertHundredNanosToMillis(secondaryMedianLatency) << "ms\n";
    std::cout << "Median effective latency on combined interfaces: " << ConvertHundredNanosToMillis(effectiveMedianLatency)
              << " (" << percent(primaryMedianLatency - effectiveMedianLatency, primaryMedianLatency)
              << "% improvement over primary) \n";

    // Minimum and maximum latency
    const auto primaryMinimumLatency = std::ranges::min(primaryLatencies);
    const auto primaryMaximumLatency = std::ranges::max(primaryLatencies);
    const auto secondaryMinimumLatency = std::ranges::min(secondaryLatencies);
    const auto secondaryMaximumLatency = std::ranges::max(secondaryLatencies);
    std::cout << '\n';
    std::cout << "Minimum / Maximum latency on primary interface: " << ConvertHundredNanosToMillis(primaryMinimumLatency)
              << "/" << ConvertHundredNanosToMillis(primaryMaximumLatency) << "ms\n";
    std::cout << "Minimum / Maximum latency on secondary interface: " << ConvertHundredNanosToMillis(secondaryMinimumLatency)
              << "/" << ConvertHundredNanosToMillis(secondaryMaximumLatency) << "ms\n";
}

void DumpLatencyData(std::span<const LatencyData> data, std::ofstream& file)
{
    // Add column header
    file << "Sequence number, Primary Send timestamp (100ns), Primary Echo timestamp (100ns), Primary Receive "
            "timestamp (100ns), "
         << "Secondary Send timestamp (100ns), Secondary Echo timestamp (100ns), Secondary Receive timestamp (100ns)\n";
    // Add raw timestamp data
    for (auto i = 0; i < data.size(); ++i)
    {
        const auto& stat = data[i];
        file << i << ", ";
        file << stat.m_primarySendTimestamp << ", " << stat.m_primaryEchoTimestamp << ", " << stat.m_primaryReceiveTimestamp << ", ";
        file << stat.m_secondarySendTimestamp << ", " << stat.m_secondaryEchoTimestamp << ", " << stat.m_secondaryReceiveTimestamp;
        file << "\n";
    }
}

} // namespace multipath