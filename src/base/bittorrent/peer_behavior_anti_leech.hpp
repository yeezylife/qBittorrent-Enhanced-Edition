#pragma once

// Behavioral anti-leech engine (PeerBanHelper-style).
//
// Implements three closely related detection modules that operate on sampling
// each connection's actual transfer counters rather than on client signatures:
//
//   1. 进度检查器 / Progress-Cheat Blocker (PCB)
//       - under-reported progress : we know how many bytes we uploaded to a
//         peer (peer_info::total_upload). That sets a *minimum* download each
//         peer must genuinely have. If the peer reports a progress much lower
//         than that minimum, it is lying about its progress -> ban.
//       - progress rewind / reset : we remember the highest progress each
//         IP-group ever reported. If a (re)connecting peer reports progress
//         that dropped more than the allowed rewind, it faked progress -> ban.
//       - excess download : if we uploaded to one peer more than the whole
//         torrent (x threshold), the peer is a cyclic downloader -> ban.
//   2. 多拨封禁 / Multi-dial blocker
//       - counts *distinct* IPs inside one subnet that are connected to the
//         same torrent. Beyond a tolerance it is treated as one user hogging
//         many connections to refuse to trade -> ban the whole subnet.
//   3. 自动范围封禁 / Auto range-ban
//       - whenever an IP is banned the neighbouring /30 (v4) /60 (v6) range
//         is banned too, and every peer in it self-disconnects.
//
// NOTE ON THREADING / DEADLOCKS
// All callbacks of a libtorrent plugin run on the libtorrent network thread.
// Calling any blocking *public* session/torrent API from there (get_torrents,
// torrent_handle::get_peer_info, set_ip_filter, ...) deadlocks. Therefore this
// implementation performs NO session-wide enumeration: every peer plugin
// maintains the shared state, and enforcement is done by each peer
// disconnecting *itself* when its own address ends up on a ban list. The only
// libtorrent APIs touched from inside the plugin are peer_connection_handle
// (get_peer_info / disconnect), which are designed to be plugin-safe.
//
// The queueing decision thresholds below are intentionally *aggressive*
// ("宁错杀不放过"): tune them down if you get too many false positives.

#include <array>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include <boost/asio/error.hpp>

#include <libtorrent/address.hpp>
#include <libtorrent/extensions.hpp>
#include <libtorrent/peer_connection_handle.hpp>
#include <libtorrent/peer_info.hpp>
#include <libtorrent/socket.hpp>

#include <QString>

#include "base/logger.h"
#include "peer_filter_plugin.hpp" // defines the `client_data` type alias

namespace
{

// ---------------------------------------------------------------------------
// Aggressive detection thresholds (extreme / strict mode)
// ---------------------------------------------------------------------------

// Skip all behavioral checks for torrents smaller than this (bytes). Too small
// torrents leave peers no chance to sync genuine progress, causing false bans.
constexpr std::int64_t kMinTorrentSizeBytes = 20 * 1024 * 1024;

// Require us to have uploaded at least this fraction of the torrent to a peer
// before trusting our view of its minimum download. Avoids flagging brand new
// barely-connected peers.
constexpr float kProgressFraudMinUpload = 0.05f;

// If peer reports a progress that is more than this much *below* the fraction
// we actually uploaded to it, it is reporting fake progress.
constexpr float kMaxProgressDiff = 0.02f;

// Allowed progress rewind between connections (fraction). Pity epsilon for
// legitimately-corrupted / re-downloaded pieces.
constexpr float kRewindMaxDiff = 0.02f;

// Only treat a progress drop as rewind cheating if the peer previously claimed
// at least this much progress. Small progress can wobble harmlessly.
constexpr float kRewindMinMaxProgress = 0.20f;

// How many seconds a connection must have survived (and completed its
// handshake) before its reported progress is trusted for the progress-based
// detections. Without this grace period a reconnecting seeder that briefly
// reports 0% until its bitfield arrives would be false-banned. Leechers that
// fake a low progress remain low and are caught after this grace period.
constexpr int kStabilizeTicks = 3;

// Ban peers whose cumulative download from us exceeds torrent size * factor.
constexpr bool kBlockExcessive = true;
constexpr float kExcessiveThreshold = 1.1f;

// Multi-dial subnet prefixes.
constexpr int kSubnetV4 = 24;
constexpr int kSubnetV6 = 60;
// Distinct IPs of the same subnet connected to the same torrent that are
// tolerated. Ban once the count is *above* these values.
constexpr int kTolerateV4 = 1;
constexpr int kTolerateV6 = 2;

constexpr std::uint64_t kFNV1aOffset = 14695981039346656037ULL;
constexpr std::uint64_t kFNV1aPrime = 1099511628211ULL;

// FNV-1a 64-bit one-way hash. Used *only* to tell distinct IPv6 addresses
// apart for counting; not used as a ban identity.
std::uint64_t fnv1a64(const unsigned char *p, std::size_t n)
{
    std::uint64_t h = kFNV1aOffset;
    for (std::size_t i = 0; i < n; ++i)
    {
        h ^= p[i];
        h *= kFNV1aPrime;
    }
    return h;
}

// Per-IP address classification. v4 uses a plain 32-bit host; v6 uses a 60-bit
// prefix for grouping (a home user is treated as one face) plus a full-address
// hash to tell distinct addresses apart for the multi-dial counter.
struct peer_identity
{
    bool ok = false;
    bool v4 = false;

    std::uint32_t host = 0;        // full IPv4 address
    std::uint32_t subnet24 = 0;    // IPv4 /24
    std::uint32_t subnet30 = 0;    // IPv4 /30
    std::uint64_t v6prefix = 0;    // IPv6 /60
    std::uint64_t v6id = 0;        // IPv6 identity (hashed full address)

    std::uint64_t groupKey() const { return v4 ? host : v6prefix; }
};

peer_identity classify_peer(const lt::address &addr)
{
    peer_identity out;
    if (addr.is_v4())
    {
        const auto b = addr.to_v4().to_bytes();
        out.ok = true;
        out.v4 = true;
        out.host = (static_cast<std::uint32_t>(b[0]) << 24)
                 | (static_cast<std::uint32_t>(b[1]) << 16)
                 | (static_cast<std::uint32_t>(b[2]) << 8)
                 | static_cast<std::uint32_t>(b[3]);
        out.subnet30 = out.host & 0xFFFFFFFCu;
        out.subnet24 = out.host & 0xFFFFFF00u;
    }
    else if (addr.is_v6())
    {
        const auto b = addr.to_v6().to_bytes();
        out.ok = true;
        out.v4 = false;
        std::uint64_t hi = 0;
        for (int i = 0; i < 8; ++i)
            hi = (hi << 8) | b[i];
        out.v6prefix = hi & 0xFFFFFFFFFFFFFFF0ULL;
        out.v6id = fnv1a64(b.data(), 16);
    }
    return out;
}

// Per torrent + IP-group tracked facts (kept across reconnects to survive the
// "cache-forgetting" trick).
struct peer_track
{
    std::int64_t maxUpload = 0;   // most bytes we have ever uploaded to this group
    float maxProgress = -1.0f;    // highest progress this group ever claimed
};

// Shared, cross-torrent anti-leech state. Only ever modified by plugin
// callbacks, all of which run on the single libtorrent network thread, so no
// locking is required.
struct behavior_state
{
    // PCB tracking: torrentId -> ip-group -> track
    std::unordered_map<std::uint32_t, std::unordered_map<std::uint64_t, peer_track>> track;

    // multi-dial membership: torrentId -> subnet -> (ip identity -> live conn count)
    std::unordered_map<std::uint32_t, std::unordered_map<std::uint32_t, std::unordered_map<std::uint32_t, int>>> subnetsV4;
    std::unordered_map<std::uint32_t, std::unordered_map<std::uint64_t, std::unordered_map<std::uint64_t, int>>> subnetsV6;

    // global ban lists
    std::unordered_set<std::uint64_t> bannedExact;      // v4 host / v6 /60 key
    std::unordered_set<std::uint32_t> bannedSubnet30;   // v4 /30 (auto range-ban)
    std::unordered_set<std::uint32_t> bannedSubnet24;   // v4 /24 (multi-dial)
    std::unordered_set<std::uint64_t> bannedSubnet60;   // v6 /60 (range + multi-dial)
};

// ---- peer plugin ------------------------------------------------
class peer_behavior_plugin final : public lt::peer_plugin
{
public:
    peer_behavior_plugin(std::shared_ptr<behavior_state> state, std::uint32_t torrentId
                         , std::int64_t torrentSize, lt::peer_connection_handle ph)
        : m_state(std::move(state))
        , m_torrentId(torrentId)
        , m_torrentSize(torrentSize)
        , m_peer(ph)
    {
    }

    void tick() override
    {
        if (m_state && !m_attached)
            return;

        ++m_ticks;

        lt::peer_info info;
        m_peer.get_peer_info(info);

        const auto ident = classify_peer(info.ip.address());
        if (!ident.ok)
            return; // I2P / non-IP connection, ignore

        registerMembership(ident);
        updateMultiDial(ident);

        if (isBanned(ident))
        {
            disconnectNow();
            return;
        }

        runDetections(info, ident);
    }

    void on_disconnect(const boost::system::error_code &) override
    {
        if (m_state && m_registered)
        {
            if (m_identity.v4)
            {
                auto &subnetMap = m_state->subnetsV4[m_torrentId][m_identity.subnet24];
                auto it = subnetMap.find(m_identity.host);
                if (it != subnetMap.end())
                {
                    if (it->second <= 1)
                        subnetMap.erase(it);
                    else
                        --it->second;
                }
            }
            else
            {
                auto &subnetMap = m_state->subnetsV6[m_torrentId][m_identity.v6prefix];
                auto it = subnetMap.find(m_identity.v6id);
                if (it != subnetMap.end())
                {
                    if (it->second <= 1)
                        subnetMap.erase(it);
                    else
                        --it->second;
                }
            }
            m_registered = false;
            m_attached = false;
        }
    }

private:
    void registerMembership(const peer_identity &ident)
    {
        if (m_registered)
            return;

        m_identity = ident;
        if (ident.v4)
            ++m_state->subnetsV4[m_torrentId][ident.subnet24][ident.host];
        else
            ++m_state->subnetsV6[m_torrentId][ident.v6prefix][ident.v6id];
        m_registered = true;
    }

    // Multi-dial blocking: if too many distinct IPs of one subnet are attached
    // to the same torrent, nuke the whole subnet.
    void updateMultiDial(const peer_identity &ident)
    {
        if (ident.v4)
        {
            const auto &subnetMap = m_state->subnetsV4[m_torrentId][ident.subnet24];
            if (subnetMap.size() > kTolerateV4)
                banSubnetV4(ident.subnet24);
        }
        else
        {
            const auto &subnetMap = m_state->subnetsV6[m_torrentId][ident.v6prefix];
            if (subnetMap.size() > kTolerateV6)
                banSubnetV6(ident.v6prefix);
        }
    }

    bool isBanned(const peer_identity &ident) const
    {
        if (ident.v4)
            return m_state->bannedExact.count(ident.host)
                   || m_state->bannedSubnet30.count(ident.subnet30)
                   || m_state->bannedSubnet24.count(ident.subnet24);
        return m_state->bannedSubnet60.count(ident.v6prefix);
    }

    void runDetections(const lt::peer_info &info, const peer_identity &ident)
    {
        if (m_torrentSize < kMinTorrentSizeBytes)
            return;

        // Progress is not trustworthy while the peer is still handshaking, or for
        // the first few seconds of a connection (a reconnecting seeder can report
        // 0% until it sends its bitfield). Jumping to bans then would nuke
        // legitimate peers. Leechers that fake a low progress stay low and are
        // caught once the connection stabilises.
        if ((info.flags & lt::peer_info::handshake) || (m_ticks < kStabilizeTicks))
            return;

        float progress = info.progress;
        if (progress < 0.0f)
            progress = 0.0f;
        if (progress > 1.0f)
            progress = 1.0f;

        peer_track &trk = m_state->track[m_torrentId][ident.groupKey()];

        // (1) Excess download : uploaded to a single peer more than a whole torrent.
        if (kBlockExcessive
                && (info.total_upload > static_cast<std::int64_t>(static_cast<double>(m_torrentSize) * kExcessiveThreshold)))
        {
            banExact(ident, "Excess download");
            return;
        }

        // (2) Under-reported progress : the share of the torrent we uploaded sets the
        //     minimum it must have downloaded; reporting far less is cheating.
        const double uploadFrac = static_cast<double>(info.total_upload) / static_cast<double>(m_torrentSize);
        if ((uploadFrac >= static_cast<double>(kProgressFraudMinUpload))
                && ((static_cast<float>(uploadFrac) - progress) > kMaxProgressDiff))
        {
            banExact(ident, "Progress fraud");
            return;
        }

        // (3) Progress rewind : a (re)connecting peer that previously claimed a
        //     large progress and now reports much less faked its numbers.
        if ((trk.maxProgress >= kRewindMinMaxProgress)
                && (progress >= 0.0f)
                && (trk.maxProgress - progress) > kRewindMaxDiff)
        {
            banExact(ident, "Progress rewind");
            return;
        }

        // Update the persistent record.
        if (info.total_upload > trk.maxUpload)
            trk.maxUpload = info.total_upload;
        if (progress > trk.maxProgress)
        {
            trk.maxProgress = progress;
            if (trk.maxProgress > 1.0f)
                trk.maxProgress = 1.0f;
        }
    }

    void banExact(const peer_identity &ident, const char *reason)
    {
        bool newlyBanned = false;
        if (ident.v4)
        {
            newlyBanned = !m_state->bannedExact.count(ident.host);
            m_state->bannedExact.insert(ident.host);
            // auto range-ban: also cover the neighbouring /30 (v4)
            if (!m_state->bannedSubnet30.count(ident.subnet30))
            {
                m_state->bannedSubnet30.insert(ident.subnet30);
                newlyBanned = true;
            }
        }
        else
        {
            newlyBanned = !m_state->bannedSubnet60.count(ident.v6prefix);
            m_state->bannedSubnet60.insert(ident.v6prefix);
        }

        if (newlyBanned)
        {
            LogMsg(u"行为反吸血: 封禁 Peer (原因: %1, IP: %2, 种子ID: %3)"_s
                       .arg(QString::fromUtf8(reason))
                       .arg(QString::fromStdString(m_peer.remote().address().to_string()))
                       .arg(m_torrentId)
                   , Log::WARNING);
        }

        disconnectNow();
    }

    void banSubnetV4(std::uint32_t subnet24)
    {
        if (m_state->bannedSubnet24.count(subnet24))
            return;

        m_state->bannedSubnet24.insert(subnet24);
        const auto &peers = m_state->subnetsV4[m_torrentId][subnet24];
        for (const auto &kv : peers)
        {
            m_state->bannedExact.insert(kv.first);
            m_state->bannedSubnet30.insert(kv.first & 0xFFFFFFFCu);
        }

        char subnetText[16];
        std::snprintf(subnetText, sizeof(subnetText), "%u.%u.%u.%u"
                      , (subnet24 >> 24) & 0xFFu, (subnet24 >> 16) & 0xFFu, (subnet24 >> 8) & 0xFFu, subnet24 & 0xFFu);

        LogMsg(u"行为反吸血: 多拨封禁 整个 /%1 网段 (子网: %2/24)"_s
                   .arg(kSubnetV4)
                   .arg(QString::fromLatin1(subnetText))
               , Log::WARNING);

        disconnectNow();
    }

    void banSubnetV6(std::uint64_t prefix60)
    {
        if (m_state->bannedSubnet60.count(prefix60))
            return;

        m_state->bannedSubnet60.insert(prefix60);

        LogMsg(u"行为反吸血: 多拨封禁 整个 /%1 网段 (IP: %2)"_s
                   .arg(kSubnetV6)
                   .arg(QString::fromStdString(m_peer.remote().address().to_string()))
               , Log::WARNING);

        disconnectNow();
    }

    void disconnectNow()
    {
        m_peer.disconnect(boost::asio::error::connection_refused, lt::operation_t::bittorrent, lt::disconnect_severity_t{0});
    }

    std::shared_ptr<behavior_state> m_state;
    const std::uint32_t m_torrentId;
    const std::int64_t m_torrentSize;
    lt::peer_connection_handle m_peer;
    peer_identity m_identity;
    int m_ticks = 0;
    bool m_registered = false;
    bool m_attached = true;
};

// ---- torrent plugin ---------------------------------------------
class peer_behavior_torrent_plugin final : public lt::torrent_plugin
{
public:
    peer_behavior_torrent_plugin(std::shared_ptr<behavior_state> state, std::uint32_t torrentId
                                 , std::int64_t torrentSize)
        : m_state(std::move(state))
        , m_torrentId(torrentId)
        , m_torrentSize(torrentSize)
    {
    }

    std::shared_ptr<lt::peer_plugin> new_connection(lt::peer_connection_handle const &ph) override
    {
        return std::make_shared<peer_behavior_plugin>(m_state, m_torrentId, m_torrentSize, ph);
    }

private:
    std::shared_ptr<behavior_state> m_state;
    const std::uint32_t m_torrentId;
    const std::int64_t m_torrentSize;
};

// ---- session plugin ---------------------------------------------
class peer_behavior_monitor final : public lt::plugin
{
public:
    peer_behavior_monitor()
        : m_state(std::make_shared<behavior_state>())
    {
    }

    ~peer_behavior_monitor() override
    {
    }

    std::shared_ptr<lt::torrent_plugin> new_torrent(lt::torrent_handle const &th, client_data) override
    {
        // ignore private torrents
        if (th.torrent_file() && th.torrent_file()->priv())
            return nullptr;

        const std::int64_t size = th.torrent_file() ? th.torrent_file()->total_size() : 0;
        if (size < kMinTorrentSizeBytes)
            return nullptr;

        return std::make_shared<peer_behavior_torrent_plugin>(m_state, m_nextId++, size);
    }

private:
    std::shared_ptr<behavior_state> m_state;
    std::uint32_t m_nextId = 0;
};

} // namespace