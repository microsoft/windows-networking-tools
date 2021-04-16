#pragma once

#include <fstream>
#include <vector>

namespace multipath {

struct LatencyMeasure
{
    // All timestamps are in microseconds
    long long m_primarySendTimestamp = -1;
    long long m_secondarySendTimestamp = -1;

    long long m_primaryEchoTimestamp = -1;
    long long m_secondaryEchoTimestamp = -1;

    long long m_primaryReceiveTimestamp = -1;
    long long m_secondaryReceiveTimestamp = -1;
};

struct LatencyData
{
    std::vector<LatencyMeasure> m_latencies;

    size_t m_datagramSize = 0;
    long long m_primaryCorruptDatagrams = 0;
    long long m_secondaryCorruptDatagrams = 0;
};

void PrintLatencyStatistics(LatencyData& data);
void DumpLatencyData(const LatencyData& data, std::ofstream& file);

} // namespace multipath