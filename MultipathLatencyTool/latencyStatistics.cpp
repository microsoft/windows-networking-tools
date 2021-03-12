#include "latencyStatistics.h"

#include <iostream>
#include <limits>
#include <vector>

namespace multipath {

constexpr long long ConvertHundredNanosToMillis(long long hundredNs) noexcept
{
    return static_cast<long long>(hundredNs / 10000LL);
}

void PrintLatencyStatistics(std::span<const LatencyData> data)
{
    // simple average of latencies for received datagrams
    long long primaryLatencyTotal = 0;
    long long secondaryLatencyTotal = 0;
    long long aggregatedLatencyTotal = 0;
    long long effectiveLatencyTotal = 0;

    long long primaryReceivedFrames = 0;
    long long secondaryReceivedFrames = 0;
    long long aggregatedLatencySamples = 0;
    long long effectiveLatencySamples = 0;

    long long primaryLostFrames = 0;
    long long secondaryLostFrames = 0;
    long long aggregatedLostFrames = 0;

    long long primarySentFrames = 0;
    long long secondarySentFrames = 0;

    for (const auto& stat : data)
    {
        long long aggregatedLatency = std::numeric_limits<long long>::max();
        if (stat.m_primarySendTimestamp >= 0)
        {
            primarySentFrames += 1;
        }

        if (stat.m_primaryReceiveTimestamp >= 0)
        {
            const auto primaryLatency = stat.m_primaryReceiveTimestamp - stat.m_primarySendTimestamp;
            primaryLatencyTotal += primaryLatency;
            primaryReceivedFrames += 1;
            aggregatedLatency = primaryLatency;
        }
        else if (stat.m_primarySendTimestamp >= 0)
        {
            primaryLostFrames += 1;
        }

        if (stat.m_secondarySendTimestamp >= 0)
        {
            secondarySentFrames += 1;
        }

        if (stat.m_secondaryReceiveTimestamp >= 0)
        {
            const auto secondaryLatency = stat.m_secondaryReceiveTimestamp - stat.m_secondarySendTimestamp;
            secondaryLatencyTotal += secondaryLatency;
            secondaryReceivedFrames += 1;
            aggregatedLatency = std::min(aggregatedLatency, secondaryLatency);
        }
        else if (stat.m_secondarySendTimestamp >= 0)
        {
            secondaryLostFrames += 1;
        }

        if (stat.m_secondaryReceiveTimestamp >= 0 || stat.m_primaryReceiveTimestamp >= 0)
        {
            aggregatedLatencyTotal += aggregatedLatency;
            aggregatedLatencySamples += 1;
        }
        else
        {
            aggregatedLostFrames += 1;
        }

        if (stat.m_secondaryReceiveTimestamp >= 0 && stat.m_primaryReceiveTimestamp >= 0)
        {
            effectiveLatencyTotal += std::min(stat.m_secondaryReceiveTimestamp, stat.m_primaryReceiveTimestamp) -
                                     std::min(stat.m_secondarySendTimestamp, stat.m_primarySendTimestamp);
            effectiveLatencySamples += 1;
        }
    }

    const auto primaryAverageLatency =
        ConvertHundredNanosToMillis(primaryReceivedFrames > 0 ? primaryLatencyTotal / primaryReceivedFrames : 0);
    const auto secondaryAverageLatency =
        ConvertHundredNanosToMillis(secondaryReceivedFrames > 0 ? secondaryLatencyTotal / secondaryReceivedFrames : 0);
    const auto aggregatedAverageLatency =
        ConvertHundredNanosToMillis(aggregatedLatencySamples > 0 ? aggregatedLatencyTotal / aggregatedLatencySamples : 0);
    const auto effectiveAverageLatency =
        ConvertHundredNanosToMillis(effectiveLatencySamples > 0 ? effectiveLatencyTotal / effectiveLatencySamples : 0);
    const auto aggregatedSendFrames = std::max(primarySentFrames, secondarySentFrames);

    std::cout << '\n';
    std::cout << "Sent frames on primary interface: " << primarySentFrames << '\n';
    std::cout << "Sent frames on secondary interface: " << secondarySentFrames << '\n';

    std::cout << '\n';
    std::cout << "Received frames on primary interface: " << primaryReceivedFrames << " ("
              << (primarySentFrames > 0 ? primaryReceivedFrames * 100 / primarySentFrames : 0) << "%)\n";
    std::cout << "Received frames on secondary interface: " << secondaryReceivedFrames << " ("
              << (secondarySentFrames > 0 ? secondaryReceivedFrames * 100 / secondarySentFrames : 0) << "%)\n";

    std::cout << '\n';
    std::cout << "Average latency on primary interface: " << primaryAverageLatency << '\n';
    std::cout << "Average latency on secondary interface: " << secondaryAverageLatency << '\n';
    std::cout << "Average minimum latency on combined interface: " << aggregatedAverageLatency << " ("
              << (primaryAverageLatency > 0 ? (primaryAverageLatency - aggregatedAverageLatency) * 100 / primaryAverageLatency : 0)
              << "% improvement over primary) \n";
    std::cout << "Average effective latency on combined interface: " << effectiveAverageLatency << " ("
              << (primaryAverageLatency > 0 ? (primaryAverageLatency - effectiveAverageLatency) * 100 / primaryAverageLatency : 0)
              << "% improvement over primary) \n";

    std::cout << '\n';
    std::cout << "Lost frames on primary interface: " << primaryLostFrames << " ("
              << (primarySentFrames > 0 ? (primaryLostFrames * 100 / primarySentFrames) : 0) << "%)\n";
    std::cout << "Lost frames on secondary interface: " << secondaryLostFrames << " ("
              << (secondarySentFrames > 0 ? (secondaryLostFrames * 100 / secondarySentFrames) : 0) << "%)\n";
    std::cout << "Lost frames on both interface simultaneously: " << aggregatedLostFrames << " ("
              << (aggregatedSendFrames > 0 ? (aggregatedLostFrames * 100 / aggregatedSendFrames) : 0) << "%)\n";
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