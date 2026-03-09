// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_IBD_PEER_H
#define BITCOIN_NET_IBD_PEER_H

#include <chrono>
#include <cstdint>
#include <optional>

class CNode;

/**
 * IBD peer scoring constants and configuration.
 * These can be adjusted to tune the preferential peer behavior during Initial Block Download.
 */

// Default epoch duration: how often we evaluate peer quality during IBD
static constexpr std::chrono::seconds DEFAULT_IBD_PEER_EPOCH_LENGTH{60};

// Minimum number of full relay peers required before we consider swapping
static constexpr int IBD_PEER_MIN_PEERS{2};

// Score threshold below which we try to find a better peer (lower = stricter)
static constexpr double IBD_PEER_SCORE_THRESHOLD{0.5};

// Number of epochs a peer must perform poorly before we disconnect
static constexpr int IBD_PEER_EPOCHS_BEFORE_DISCONNECT{3};

// Maximum attempts to find a better peer per epoch
static constexpr int IBD_PEER_MAX_SWAP_ATTEMPTS{5};

/**
 * IBDPeerScore - tracks peer quality metrics during Initial Block Download
 */
struct IBDPeerScore {
    int64_t node_id{0};
    std::chrono::microseconds min_ping{std::chrono::microseconds::max()};
    uint64_t total_bytes{0};
    std::chrono::seconds connected_time{std::chrono::seconds::zero()};
    int poor_epoch_count{0};  // Number of epochs peer scored below threshold

    /**
     * Calculate a normalized score for this peer.
     * Higher is better. Range: [0.0, 1.0]
     * 
     * Score is based on:
     * - Latency (ping time) - lower is better
     * - Bandwidth (total bytes transferred) - higher is better
     * - Connection stability (time connected) - longer is better
     */
    double CalculateScore() const;

    /**
     * Check if this peer should be considered for replacement.
     */
    bool ShouldReplace() const;
};

/**
 * Get the minimum ping time for a peer in microseconds.
 */
std::chrono::microseconds GetPeerMinPing(const CNode* node);

/**
 * Get total bytes transferred (send + receive) for a peer.
 */
uint64_t GetPeerTotalBytes(const CNode* node);

/**
 * Calculate peer score for IBD purposes.
 * Returns nullopt if not enough data to score.
 */
std::optional<IBDPeerScore> CalculateIBDScore(const CNode* node);

/**
 * Log IBD peer scoring information.
 */
void LogIBDPeerScore(const IBDPeerScore& score);

#endif // BITCOIN_NET_IBD_PEER_H
