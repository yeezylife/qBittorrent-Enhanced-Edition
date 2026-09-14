#pragma once

// Behavioral anti-leech engine, logic aligned to PBH-BTN/PeerBanHelper's
// ProgressCheatBlocker, MultiDialingBlocker and AutoRangeBan modules.
//
// Implements three closely related detection modules that operate on sampling
// each connection's actual transfer counters rather than on client signatures:
//
//   1. 进度检查器 / Progress-Cheat Blocker (PCB)
//       - under-reported progress / difference : we accumulate how many bytes we
//         uploaded to an IP-group across reconnects (PBH "tracking uploaded
//         increase total"). That cumulative count sets a *minimum* the peer must
//         genuinely have downloaded. If it reports noticeably less, it is lying
//         -> ban (PBH differenceTest).
//       - progress rewind : the highest non-zero progress an IP-group ever
//         reported vs. what it reports now. Dropping more than allowed means it
//         reset/faked its progress -> ban (PBH progressRewind).
//       - excess download : cumulative uploads exceeding the torrent size
//         (floored at the minimum torrent size) x threshold -> ban (PBH
//         excessiveClient).
//       - every progress-based suspicion must persist for a short confirmation
//         window (PBH "max-wait-duration" / ban-delay window) before it is acted
//         on, and a 0% report is never trusted or stored. This is what makes a
//         reconnecting seeder (brief 0% until its bitfield arrives) safe from
//         false bans while cheating low-reporting peers are still caught.
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
#include <algorithm>
#include <chrono>
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

// PBH "maximum-difference": if the fraction of the torrent we actually uploaded
// to a peer exceeds the progress it reports by more than this, it is under-
// reporting. (PBH compares expected=computedUploaded/size vs reported.)
constexpr float kMaxProgressDiff = 0.02f;

// PBH "rewind-maximum-difference": how much progress a peer may drop between
// reports before we consider it to have faked progress (reconnect reset).
constexpr float kRewindMaxDiff = 0.02f;

// PBH "max-wait-duration" (ms): the confirmation window. A progress-based
// suspicion is only acted on once it persists for at least this long, so a
// brief transient (e.g. a reconnecting seeder reporting 0 until its bitfield
// arrives) never triggers a false ban.
constexpr std::int64_t kBanConfirmDelayMs = 1500;

// Ban peers whose cumulative download from us exceeds this threshold.
constexpr bool kBlockExcessive = true;
// PBH floors the allowed excess at max(torrentSize, torrentMinimumSize).
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

// Steady monotonic clock in milliseconds. Only used for the confirmation
// window (no wall-time / timezone handling needed).
std::int64_t nowMs()
{
    using namespace std::chrono;
    return time_point_cast<milliseconds>(steady_clock::now()).time_since_epoch().count();
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

// Per torrent + IP-group tracked facts (kept across reconnects so a cyclic
// downloader cannot defeat us by disconnecting and reconnecting at 0%).
struct peer_track
{
    // Cumulative bytes we have ever (admittedly) uploaded to this group of IPs
    // for this torrent, summed across connections. This is PBH's "tracking
    // uploaded increase total": it makes the excess/progress checks immune to
    // per-connection counter resets.
    std::int64_t statusUploaded = 0;

    // Last *non-zero* progress this group reported. PBH never stores 0.0 so a
    // reconnecting seeder's transient 0% cannot poison the record and trigger a
    // false rewind ban on the next reconnect.
    float lastReportProgress = -1.0f;

    // Steady-clock millisecond timestamp when the last progress-based suspicion
    // was first observed (PBH "ban-delay window"). 0 = no active suspicion.
    std::int64_t suspectSinceMs = 0;
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

        // PBH hands peers still in the handshake the "handshaking" pass; their
        // reported progress (0) is not yet trustworthy.
        if (info.flags & lt::peer_info::handshake)
            return;

        const std::int64_t now = nowMs();
        const float progress = std::clamp(info.progress, 0.0f, 1.0f);
        peer_track &trk = m_state->track[m_torrentId][ident.groupKey()];

        // ---- Cumulative upload tracking (PBH "总上传量/增量") -----------------
        // Survives per-connection counter resets, so a cyclic downloader cannot
        // defeat the checks by disconnecting/reconnecting at 0%.
        const std::int64_t cur = info.total_upload;
        trk.statusUploaded += m_hasPrevTotal
            ? ((cur >= m_lastUpload) ? (cur - m_lastUpload) : cur)  // reset -> whole value is fresh
            : cur;                                                  // first observation of this connection
        m_lastUpload = cur;
        m_hasPrevTotal = true;

        // PBH isUploadingToPeer: only judge a peer we are actually uploading to.
        const bool uploading = (info.total_upload > 0) || (info.up_speed > 0);
        const double computedProgress = static_cast<double>(trk.statusUploaded) / static_cast<double>(m_torrentSize);

        // ---- (1) Excess download (PBH excessiveClient) -----------------------
        // Uses the cumulative upload count, and floors the allowed excess at
        // max(torrentSize, minimumSize) exactly like PBH.
        if (kBlockExcessive && (trk.statusUploaded > m_torrentSize))
        {
            const std::int64_t allowed = static_cast<std::int64_t>(
                static_cast<double>(std::max(m_torrentSize, kMinTorrentSizeBytes)) * kExcessiveThreshold);
            if (trk.statusUploaded > allowed)
            {
                clearSuspicion(trk);
                banExact(ident, "Excess download");
                return;
            }
        }

        if (!uploading)          // PBH early pass: no uploads -> no progress judgement
            return;

        // If the peer reports at least the progress we computed from uploads, it
        // cannot be under-reporting; skip the progress checks (PBH).
        if (computedProgress <= progress)
        {
            clearSuspicion(trk);
            return;
        }

        const double difference = computedProgress - progress;

        // ---- (2) Under-reported progress (PBH differenceTest) ---------------
        // Difference above the threshold persists for the confirmation window.
        if (difference > kMaxProgressDiff)
        {
            if (confirmSuspicion(trk, now))
            {
                clearSuspicion(trk);
                banExact(ident, "Progress fraud");
                return;
            }
        }
        else
        {
            clearSuspicion(trk);
        }

        // ---- (3) Progress rewind (PBH progressRewind) ----------------------
        // Peer previously reported a higher (non-zero) progress and now reports
        // much less, i.e. it faked/reset. Unless the current progress is
        // non-zero (peer already sent its bitfield), we wait out the window so a
        // reconnecting seeder's brief 0% cannot false-ban it.
        if (kRewindMaxDiff > 0.0f)
        {
            const float lastReported = trk.lastReportProgress;
            if (lastReported >= 0.0f)
            {
                const double rewind = static_cast<double>(lastReported) - progress;
                if (rewind > kRewindMaxDiff)
                {
                    if ((progress > 0.0f) || confirmSuspicion(trk, now))
                    {
                        clearSuspicion(trk);
                        banExact(ident, "Progress rewind");
                        return;
                    }
                }
            }
        }

        // ---- Persist (PBH finally block) ------------------------------------
        if (progress != 0.0f)          // never store a 0 report, avoid poisoning
            trk.lastReportProgress = progress;
    }

    // PBH "ban-delay window": arm the confirmation timer on the first
    // observation of a suspicion; return true (ban) only once it has persisted
    // for at least kBanConfirmDelayMs. A transient clears the timer instead.
    bool confirmSuspicion(peer_track &trk, std::int64_t now)
    {
        if (trk.suspectSinceMs == 0)
        {
            trk.suspectSinceMs = now;
            return false;
        }
        return (now - trk.suspectSinceMs) >= kBanConfirmDelayMs;
    }

    void clearSuspicion(peer_track &trk)
    {
        trk.suspectSinceMs = 0;
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
    std::int64_t m_lastUpload = 0;   // last observed total_upload on this connection
    bool m_hasPrevTotal = false;     // whether m_lastUpload is meaningful yet
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