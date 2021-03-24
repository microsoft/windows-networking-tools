#pragma once

#include <span>
#include <fstream>

namespace multipath {

struct LatencyData
{
    long long m_primarySendTimestamp = -1;
    long long m_secondarySendTimestamp = -1;

    long long m_primaryEchoTimestamp = -1;
    long long m_secondaryEchoTimestamp = -1;

    long long m_primaryReceiveTimestamp = -1;
    long long m_secondaryReceiveTimestamp = -1;
};

void PrintLatencyStatistics(std::span<const LatencyData> data);
void DumpLatencyData(std::span<const LatencyData> data, std::ofstream& file);

} // namespace multipath