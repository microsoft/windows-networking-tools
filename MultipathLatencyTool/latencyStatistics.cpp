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

    auto latency = [](const auto& timestamps) { return timestamps.second - timestamps.first; };
    auto minimumLatency = [](const LatencyData& stat) {
        auto minLatency = std::numeric_limits<long long>::max();
        if (stat.m_primaryReceiveTimestamp >= 0)
        {
            minLatency = std::min(minLatency, stat.m_primaryReceiveTimestamp - stat.m_primarySendTimestamp);
        }
        if (stat.m_secondaryReceiveTimestamp >= 0)
        {
            minLatency = std::min(minLatency, stat.m_secondaryReceiveTimestamp - stat.m_secondarySendTimestamp);
        }
        return minLatency;
    };

    auto average = [](auto& data) { return data.size() > 0 ? accumulate(data, 0LL) / data.size() : 0LL; };
    auto percent = [](auto a, auto b) { return b > 0 ? a * 100 / b : 0; };

    // Compute latencies on primary, secondary or both simultaneously
    auto primaryLatencies = to_vector(data | transform(selectPrimary) | filter(received) | transform(latency), data.size());
    auto secondaryLatencies = to_vector(data | transform(selectSecondary) | filter(received) | transform(latency), data.size());
    auto minimumLatencies = to_vector(data | filter(receivedOnOneInterface) | transform(minimumLatency), data.size());
    auto effectiveLatencies = to_vector(data | transform(selectEffective) | filter(received) | transform(latency), data.size());

    long long primaryReceivedFrames = primaryLatencies.size();
    long long secondaryReceivedFrames = secondaryLatencies.size();
    long long aggregatedReceivedFrames = minimumLatencies.size();

    long long primarySentFrames =
        std::ranges::count_if(data, [](const auto& stat) { return stat.m_primarySendTimestamp >= 0; });
    long long secondarySentFrames =
        std::ranges::count_if(data, [](const auto& stat) { return stat.m_secondarySendTimestamp >= 0; });
    long long aggregatedSentFrames = std::ranges::count_if(
        data, [](const auto& stat) { return stat.m_primarySendTimestamp >= 0 || stat.m_secondarySendTimestamp >= 0; });

    // Get the average latency
    const auto primaryAverageLatency = ConvertHundredNanosToMillis(average(primaryLatencies));
    const auto secondaryAverageLatency = ConvertHundredNanosToMillis(average(secondaryLatencies));
    const auto aggregatedAverageLatency = ConvertHundredNanosToMillis(average(minimumLatencies));
    const auto effectiveAverageLatency = ConvertHundredNanosToMillis(average(effectiveLatencies));

    std::cout << '\n';
    std::cout << "Sent frames on primary interface: " << primarySentFrames << '\n';
    std::cout << "Sent frames on secondary interface: " << secondarySentFrames << '\n';

    std::cout << '\n';
    std::cout << "Received frames on primary interface: " << primaryReceivedFrames << " ("
              << percent(primaryReceivedFrames, primarySentFrames) << "%)\n";
    std::cout << "Received frames on secondary interface: " << secondaryReceivedFrames << " ("
              << percent(secondaryReceivedFrames, secondarySentFrames) << "%)\n";

    std::cout << '\n';
    std::cout << "Average latency on primary interface: " << primaryAverageLatency << '\n';
    std::cout << "Average latency on secondary interface: " << secondaryAverageLatency << '\n';
    std::cout << "Average minimum latency on both interface: " << aggregatedAverageLatency << " ("
              << percent(primaryAverageLatency - aggregatedAverageLatency, primaryAverageLatency)
              << "% difference with primary) \n";
    std::cout << "Average effective latency on combined interface: " << effectiveAverageLatency << " ("
              << percent(primaryAverageLatency - effectiveAverageLatency, primaryAverageLatency)
              << "% difference with primary) \n";

    long long primaryLostFrames = primarySentFrames - primaryReceivedFrames;
    long long secondaryLostFrames = secondarySentFrames - secondaryReceivedFrames;
    long long aggregatedLostFrames = aggregatedSentFrames - aggregatedReceivedFrames;

    std::cout << '\n';
    std::cout << "Lost frames on primary interface: " << primaryLostFrames << " ("
              << percent(primaryLostFrames, primarySentFrames) << "%)\n";
    std::cout << "Lost frames on secondary interface: " << secondaryLostFrames << " ("
              << percent(secondaryLostFrames, secondarySentFrames) << "%)\n";
    std::cout << "Lost frames on both interface simultaneously: " << aggregatedLostFrames << " ("
              << percent(aggregatedLostFrames, aggregatedSentFrames) << "%)\n";
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

}