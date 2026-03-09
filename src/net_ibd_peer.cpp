// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_ibd_peer.h>

#include <logging.h>
#include <net.h>

#include <algorithm>
#include <cmath>
#include <limits>

std::chrono::microseconds GetPeerMinPing(const CNode* node)
{
    if (!node) return std::chrono::microseconds::max();
    return node->m_min_ping_time.load();
}

uint64_t GetPeerTotalBytes(const CNode* node)
{
    if (!node) return 0;
    // These are plain uint64_t members in CNode, not atomic
    return node->nSendBytes + node->nRecvBytes;
}

std::optional<IBDPeerScore> CalculateIBDScore(const CNode* node)
{
    if (!node) return std::nullopt;

    // Only score outbound full relay peers
    if (!node->IsFullOutboundConn()) return std::nullopt;

    // Need at least one successful ping
    auto min_ping = GetPeerMinPing(node);
    if (min_ping == std::chrono::microseconds::max() || min_ping.count() <= 0) {
        return std::nullopt;
    }

    IBDPeerScore score;
    score.node_id = node->GetId();
    score.min_ping = min_ping;
    score.total_bytes = GetPeerTotalBytes(node);
    // m_connected is a const member, access it directly
    score.connected_time = node->m_connected;

    return score;
}

double IBDPeerScore::CalculateScore() const
{
    // Normalize ping time: assume 0ms - 5000ms range, lower is better
    // Normalize to [0, 1] where 1 is best (lowest ping)
    constexpr double MAX_PING_US = 5'000'000.0; // 5 seconds
    double ping_val = static_cast<double>(min_ping.count());
    double ping_score = 1.0 - (std::min(ping_val, MAX_PING_US) / MAX_PING_US);

    // Normalize bandwidth: assume 0 - 100MB range, higher is better
    constexpr double MAX_BYTES = 100'000'000.0; // 100 MB
    double bandwidth_score = std::min(static_cast<double>(total_bytes), MAX_BYTES) / MAX_BYTES;

    // Connection stability: longer is better, cap at 10 minutes
    constexpr auto MAX_STABLE_TIME = std::chrono::minutes{10};
    double stability_score = 1.0;
    if (connected_time > std::chrono::seconds{1}) {
        stability_score = std::min(
            static_cast<double>(connected_time.count()) / static_cast<double>(MAX_STABLE_TIME.count()),
            1.0
        );
    }

    // Weighted score: bandwidth 50%, latency 35%, stability 15%
    // During IBD, bandwidth is critical
    double final_score = (bandwidth_score * 0.5) + (ping_score * 0.35) + (stability_score * 0.15);

    return final_score;
}

bool IBDPeerScore::ShouldReplace() const
{
    return poor_epoch_count >= IBD_PEER_EPOCHS_BEFORE_DISCONNECT;
}

void LogIBDPeerScore(const IBDPeerScore& score)
{
    LogDebug(BCLog::NET, "IBD Peer %lld: ping=%lluus, bytes=%llu, time=%lds, score=%.2f, poor_epochs=%d\n",
        static_cast<long long>(score.node_id),
        static_cast<unsigned long long>(score.min_ping.count()),
        static_cast<unsigned long long>(score.total_bytes),
        static_cast<long>(score.connected_time.count()),
        score.CalculateScore(),
        score.poor_epoch_count);
}
