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
//       - whenever an IP is banned the neighbouring /30 (v4) /48 (v6) range
//         is banned too, and every peer in it self-disconnects.
//
// NOTE ON THREADING / DEADLOCKS
// All callbacks of a libtorrent plugin run on the libtorrent network thread.
// Calling most *public* session/torrent APIs from there (session::get_torrents,
// session::set_ip_filter, ...) deadlocks. Therefore this implementation
// performs NO session-wide enumeration: every peer plugin maintains the shared
// state, and enforcement is done by each peer disconnecting *itself* when its
// own address ends up on a ban list. The only libtorrent APIs touched from
// inside a plugin are peer_connection_handle (get_peer_info / disconnect) and a
// lazy, cache-only torrent_handle::torrent_file() used once to resolve a
// magnet's size / private flag - both are safe to call on the network thread.
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
#include <vector>

#include <atomic>

#include <boost/asio/error.hpp>

#include <libtorrent/address.hpp>
#include <libtorrent/extensions.hpp>
#include <libtorrent/peer_connection_handle.hpp>
#include <libtorrent/peer_info.hpp>
#include <libtorrent/torrent_handle.hpp>
#include <libtorrent/socket.hpp>

#include <QByteArray>
#include <QFile>
#include <QObject>
#include <QTextStream>
#include <QString>
#include <QStringList>

#include "base/net/downloadmanager.h"
#include "base/path.h"
#include "base/profile.h"
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
// PBH floors the allowed excess at max(torrentSize, torrentMinimumSize).
constexpr float kExcessiveThreshold = 1.1f;

// Multi-dial subnet prefixes. IPv6 grouping matches PBH (IPV6 prefix length 56).
constexpr int kSubnetV4 = 24;
constexpr int kSubnetV6 = 56;
// Auto range-ban (PBH auto-range-ban ipv6) uses a coarser IPv6 /48 so a whole
// residential prefix is covered and an attacker cannot hide by spreading IPs
// across a handful of /56s. The /48 mask appears in classify_peer.
// Distinct IPs of the same subnet connected to the same torrent that are
// tolerated. Ban once the count is *above* these values.
constexpr int kTolerateV4 = 1;
constexpr int kTolerateV6 = 2;

constexpr std::uint64_t kFNV1aOffset = 14695981039346656037ULL;
constexpr std::uint64_t kFNV1aPrime = 1099511628211ULL;

// Minimum number of parsed rules below which a freshly downloaded subscription
// body is assumed malformed/truncated (e.g. a rate-limit or captive page) and is
// discarded so the last known-good cache is kept. The live list normally carries
// ~700 rules, so a healthy body always clears this comfortably.
constexpr std::size_t kMinSubscriptionRules = 50;

// FNV-1a 64-bit one-way hash. Used *only* to tell distinct IPv6 addresses
// apart for counting; not used as a ban identity.
// NOTE: no `inline` here on purpose: this header lives in an anonymous
// namespace (internal linkage), so `inline` would be redundant with siblings
// like formatIPv4/v4Mask below.
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

// 128-bit IPv6 byte container (matches boost's address_v6::bytes_type).
using v6bytes_t = std::array<unsigned char, 16>;

// Per-IP address classification. v4 uses a plain 32-bit host; v6 uses a 56-bit
// prefix for grouping (a home user is treated as one face) plus a full-address
// hash to tell distinct addresses apart for the multi-dial counter.
struct peer_identity
{
    bool ok = false;
    bool v4 = false;

    std::uint32_t host = 0;        // full IPv4 address (/32 PCB identity)
    std::uint32_t subnet24 = 0;    // IPv4 /24
    std::uint32_t subnet30 = 0;    // IPv4 /30
    std::uint64_t v6mult = 0;      // IPv6 /56 subnet (PCB identity + multi-dial grouping)
    std::uint64_t v6arb = 0;       // IPv6 /48 subnet (auto range-ban)
    std::uint64_t v6id = 0;        // IPv6 identity (hashed full address)
    v6bytes_t bytes {};            // raw address in the 128-bit trie container (stretched v4 / full v6)

    std::uint64_t groupKey() const { return v4 ? host : v6mult; }
};

peer_identity classify_peer(const lt::address &addr)
{
    peer_identity out;
    if (addr.is_v4())
    {
        const auto b = addr.to_v4().to_bytes();
        const std::uint32_t host = (static_cast<std::uint32_t>(b[0]) << 24)
                                 | (static_cast<std::uint32_t>(b[1]) << 16)
                                 | (static_cast<std::uint32_t>(b[2]) << 8)
                                 | static_cast<std::uint32_t>(b[3]);
        out.ok = true;
        out.v4 = true;
        out.host = host;
        out.subnet30 = host & 0xFFFFFFFCu;
        out.subnet24 = host & 0xFFFFFF00u;
        // Stretch into the 128-bit trie container exactly once so the hot
        // lookup path never rebuilds it on every tick.
        out.bytes[0] = static_cast<unsigned char>(host >> 24);
        out.bytes[1] = static_cast<unsigned char>(host >> 16);
        out.bytes[2] = static_cast<unsigned char>(host >> 8);
        out.bytes[3] = static_cast<unsigned char>(host);
    }
    else if (addr.is_v6())
    {
        const auto b = addr.to_v6().to_bytes();
        out.ok = true;
        out.v4 = false;
        std::uint64_t hi = 0;
        for (int i = 0; i < 8; ++i)
            hi = (hi << 8) | b[i];
        out.v6mult = hi & 0xFFFFFFFFFFFFFF00ULL;     // /56 (PCB identity + multi-dial subnet)
        out.v6arb = hi & 0xFFFFFFFFFFFF0000ULL;      // /48 (auto range-ban)
        out.v6id = fnv1a64(b.data(), 16);
        out.bytes = b;
    }
    return out;
}

QString formatIPv4(std::uint32_t v)
{
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u"
                  , (v >> 24) & 0xFFu, (v >> 16) & 0xFFu, (v >> 8) & 0xFFu, v & 0xFFu);
    return QString::fromLatin1(buf);
}

// A subscribed CIDR (IP-network) range, as parsed from the BCR rule list.
struct subnet_v4
{
    std::uint32_t net = 0;      // network address, already masked
    std::uint32_t mask = 0;     // prefix mask
    int prefix = 0;             // 0..32
};

struct subnet_v6
{
    v6bytes_t net {};           // network bytes, already masked
    std::uint8_t prefix = 0;    // 0..128
};

std::uint32_t v4Mask(int prefix)
{
    return prefix <= 0 ? 0u : (0xFFFFFFFFu << (32 - prefix));
}

void maskV6(v6bytes_t &b, int prefix)
{
    if (prefix >= 128)
        return;
    const int full = prefix / 8;
    const int rem = prefix % 8;
    for (int i = full; i < 16; ++i)
        b[i] = 0;
    if (rem)
        b[full] = static_cast<unsigned char>(b[full] & static_cast<unsigned char>(0xFFu << (8 - rem)));
}

// Expand a 64-bit most-significant-half key (e.g. a /48 or /56 subnet derived in
// classify_peer) back into a 128-bit byte container, so a numeric ban key can be
// rendered as an IPv6 network string for the ban cache. Only used for (re)serialising
// the cache, never on a hot path.
v6bytes_t v6HiToBytes(std::uint64_t hi)
{
    v6bytes_t b {};
    for (int i = 0; i < 8; ++i)
        b[i] = static_cast<unsigned char>(hi >> (56 - 8 * i));
    return b;
}

// Stretch an IPv4 host (b[0] is the most-significant octet, as produced by
// classify_peer) into the 128-bit byte container used by the trie. Only the
// first 4 bytes are meaningful; the high bits of a v4 rule are never walked.
v6bytes_t v4HostToBytes(std::uint32_t host)
{
    v6bytes_t b {};
    b[0] = static_cast<unsigned char>(host >> 24);
    b[1] = static_cast<unsigned char>(host >> 16);
    b[2] = static_cast<unsigned char>(host >> 8);
    b[3] = static_cast<unsigned char>(host);
    return b;
}

// One node of the binary prefix trie. `banned` marks the end of an inserted
// rule (its network bits up to that node are the CIDR). Nodes live in a flat
// arena owned by subnet_trie: children are 0-based indices into that arena, so
// child[] holds a uint32 rather than a pointer. 0 means "no such child" and is
// also the root's own index, but the root is never referable as a child, so the
// sentinel never collides. At 12 bytes this packs ~5x more nodes per cache
// line than the pointer layout it replaced (24B).
struct trie_node
{
    std::uint32_t child[2] = {0, 0};
    bool banned = false;
};

// Binary prefix trie: CIDR containment in O(prefix bits), independent of the
// number of rules. A rule is stored by walking only its `prefix` leading bits;
// a query walks the peer address bits and reports a hit when any node on the
// path is a rule terminal. All nodes share one contiguous std::vector (index 0
// is the always-present root), so building a snapshot is a single geometric
// allocation sequence instead of one heap allocation + a recursive free per
// node, and every query walks strictly adjacent cache lines. Reclamation is the
// vector's own when a refresh retires the snapshot.
class subnet_trie
{
public:
    subnet_trie() = default;
    subnet_trie(const subnet_trie &) = delete;
    subnet_trie &operator=(const subnet_trie &) = delete;

    // Insert one CIDR. Only the first `prefix` bits of net are consumed; the
    // masked trailing bits (already zero in s4.net/s6.net) are irrelevant.
    void insert(const v6bytes_t &net, int prefix)
    {
        std::uint32_t idx = 0;   // index 0 is the root
        for (int bit = 0; bit < prefix; ++bit)
        {
            const int b = (net[static_cast<unsigned>(bit) >> 3] >> (7 - (bit & 7))) & 1;
            if (!m_nodes[idx].child[b])
            {
                // Store the child index, then grow; the vector may reallocate,
                // but indices survive a reallocation (unlike pointers/refs), so
                // idx stays valid and cache-coherent throughout the walk.
                m_nodes[idx].child[b] = static_cast<std::uint32_t>(m_nodes.size());
                m_nodes.push_back(trie_node{});
            }
            idx = m_nodes[idx].child[b];
        }
        m_nodes[idx].banned = true;
        if (prefix > m_maxDepth)
            m_maxDepth = prefix;   // tightens every later query to the deepest rule
    }

    // true if `addr` is contained by any inserted rule whose prefix length is
    // at most `bits`. Walks at most min(bits, m_maxDepth) nodes (never the rule
    // count): a terminal can only exist at a depth already inserted, so a v4
    // lookup caps at 32 and a v6 lookup stops at the deepest rule instead of
    // trailing the zeros of a stretched address. A /0 rule sets root.banned and
    // is matched by the first check regardless of depth.
    // Note: a /0 rule only sets root.banned and leaves m_maxDepth at 0, so
    // emptiness must also test the root flag, not just the depth.
    bool empty() const noexcept { return (m_maxDepth == 0) && !m_nodes.front().banned; }

    bool contains(const v6bytes_t &addr, int bits) const noexcept
    {
        const trie_node *const base = m_nodes.data();
        const trie_node *n = base;   // index 0 is the root
        if (n->banned)
            return true;   // a /0 rule (whole-family) covers addr
        const int depth = (bits < m_maxDepth) ? bits : m_maxDepth;
        for (int bit = 0; bit < depth && n; ++bit)
        {
            if (n->banned)
                return true;   // a higher-level prefix already covers addr
            const int b = (addr[static_cast<unsigned>(bit) >> 3] >> (7 - (bit & 7))) & 1;
            const std::uint32_t c = n->child[b];
            n = c ? base + c : nullptr;
        }
        return n && n->banned;
    }

private:
    int m_maxDepth = 0;
    std::vector<trie_node> m_nodes = {trie_node{}};   // index 0 is the always-present root
};

// An immutable snapshot of the subscribed CIDR rules (one trie per family plus
// their persistence mirrors). It is built in full on the refresh thread and
// swapped into the state as a whole, so the network thread always reads either
// the previous snapshot or the new one - never a half-parsed mix. All fields are
// const-free by convention and only mutated before the snapshot is published.
struct subscription_data
{
    subnet_trie trieV4;
    subnet_trie trieV6;
    std::vector<subnet_v4> v4;   // persistence mirror (c4 cache lines)
    std::vector<subnet_v6> v6;   // persistence mirror (c6 cache lines)
};

// Parse one BCR line into a v4 or v6 CIDR. Returns 1 = v4 filled, 2 = v6
// filled, 0 = unparseable (caller should skip the line).
int parseCIDR(const QString &token, subnet_v4 &s4, subnet_v6 &s6)
{
    const QString t = token.trimmed();
    if (t.isEmpty())
        return 0;

    QString netPart = t;
    int prefix = -1;
    const int slash = t.indexOf(QLatin1Char('/'));
    if (slash >= 0)
    {
        netPart = t.left(slash);
        // Parse the prefix digits in place, avoiding a temporary QString from
        // mid().toInt(); out-of-range values are clamped below regardless.
        std::int64_t acc = 0;
        bool valid = false;
        for (int i = slash + 1, n = t.size(); i < n; ++i)
        {
            const int d = t.at(i).digitValue();
            if (d < 0) { valid = false; break; }
            acc = acc * 10 + d;
            valid = true;
        }
        prefix = valid ? static_cast<int>(acc) : -1;
    }

    lt::address addr;
    try
    {
        addr = lt::make_address(netPart.toStdString());
    }
    catch (const std::exception &)
    {
        return 0;
    }

    if (addr.is_v4())
    {
        if (prefix < 0) prefix = 32;
        if (prefix > 32) prefix = 32;
        // A /0 line is a legitimate (if drastic) whole-family ban: with prefix 0
        // the trie_root.banned flag is set and every IPv4 address matches. This
        // reproduces the pre-trie v4Mask(0)==0 linear scan, so it is not a
        // regression; it only matters that the subscription source never lists
        // such an entry accidentally.
        s4.prefix = prefix;
        s4.mask = v4Mask(prefix);
        s4.net = classify_peer(addr).host & s4.mask;
        return 1;
    }

    if (addr.is_v6())
    {
        if (prefix < 0) prefix = 128;
        if (prefix > 128) prefix = 128;
        // A /0 line marks the whole of IPv6 for banning (trie_root.banned),
        // matching the old v6Contains(_,_,0) which always returned true. Kept as
        // intentional, policy-level behaviour for symmetry with the v4 branch.
        s6.net = addr.to_v6().to_bytes();
        maskV6(s6.net, prefix);
        s6.prefix = static_cast<std::uint8_t>(prefix);
        return 2;
    }

    return 0;
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
    std::int64_t suspectSinceMs = 0; // 0 = 未武装；即便时钟采样恰为 0，也只会让窗口晚一拍，不会误封
};

// Per-torrent detection state. Lives in behavior_state::torrents, indexed
// directly by torrentId (see below).
struct per_torrent_state
{
    // PCB tracking: ip-group -> track
    std::unordered_map<std::uint64_t, peer_track> track;

    // multi-dial membership: subnet -> (ip identity -> live conn count)
    std::unordered_map<std::uint32_t, std::unordered_map<std::uint32_t, int>> subnetsV4;
    std::unordered_map<std::uint64_t, std::unordered_map<std::uint64_t, int>> subnetsV6;
};

// Shared, cross-torrent anti-leech state. Only ever modified by plugin
// callbacks, all of which run on the single libtorrent network thread, so no
// locking is required.
struct behavior_state
{
    // Per-torrent state indexed directly by torrentId. Ids are dense and
    // sequential (peer_behavior_monitor::m_nextId++), so a vector replaces the
    // three torrent-keyed hash maps: every per-tick access drops from two
    // nested hashes (outer torrentId + inner key) to one bounds check plus a
    // pointer dereference, with far better locality for torrents with many peers.
    // Each slot is heap-allocated: a vector reallocation only moves the owning
    // unique_ptrs, never the state itself, so a cached peer_track * stays valid
    // by construction (no reliance on unordered_map move semantics).
    // Lifetime convention: ids are never recycled and slots are never erased
    // or moved (id == index must hold, and live peer plugins may cache node
    // pointers into a slot). A removed torrent's slot is simply left behind:
    // an untouched slot costs one null pointer. Do not "reclaim" with
    // erase/move; that would invalidate both the index mapping and cached
    // peer_track * anchors.
    std::vector<std::unique_ptr<per_torrent_state>> torrents;

    // global ban lists
    std::unordered_set<std::uint64_t> bannedExact;      // v4 exact host (progress/behaviour bans)
    std::unordered_set<std::uint32_t> bannedSubnet30;   // v4 /30 (auto range-ban)
    std::unordered_set<std::uint32_t> bannedSubnet24;   // v4 /24 (multi-dial)
    std::unordered_set<std::uint64_t> bannedSubnet48;   // v6 /48 (auto range-ban)
    std::unordered_set<std::uint64_t> bannedSubnet56;   // v6 /56 (multi-dial)

    // Network IP-set rules (subscribed CIDRs, e.g. PBH-BTN/BTN-Collected-Rules).
    // Published as a single immutable snapshot. The only writer is the app thread
    // (the Net::DownloadManager result callback) which swaps in a fully built
    // snapshot with an atomic pointer store; the libtorrent network thread reads
    // it in isBanned with a single acquire load and walks the returned raw
    // pointer lock- and refcount-free, because a snapshot is never freed while
    // any reader might still touch it.
    //
    // Reclamation: the writer retires the just-replaced snapshot to
    // m_retiredSnapshots instead of deleting it; every snapshot object (retired
    // and current) is freed only in ~behavior_state, which runs on the app
    // thread after the libtorrent network thread is already down. The snapshot's
    // contents (tries / persistence mirrors) are immutable and only written
    // before publication on the writer thread, so readers never race the
    // writer's data - only the publish itself, which is a single atomic pointer
    // store. This is genuinely lock-free: a plain pointer, no spinlock and no
    // refcount on the hot isBanned path (unlike atomic<shared_ptr>).
    //
    // Behavior note: because the fetch is now asynchronous, the subscription may
    // be empty for the first moments after startup (no local cache yet, refresh
    // still in flight), so IP-set bans are not enforced until the first refresh
    // succeeds. This is the intended trade-off for a non-blocking startup; the
    // cache-loaded snapshot (or an empty one) is used in the meantime.
    behavior_state()
    {
        // Size the tables once so steady-state operation never pays a rehash:
        // the ban lists only grow, and a few hundred torrents is the norm.
        torrents.reserve(128);
        bannedExact.reserve(2048);
        bannedSubnet30.reserve(1024);
        bannedSubnet24.reserve(256);
        bannedSubnet48.reserve(1024);
        bannedSubnet56.reserve(256);
    }

    // Get-or-create on the network thread (the only thread that touches
    // `torrents`). Growth is monotonic; a slot is materialised on first use,
    // and later reallocations never move the heap state behind a cached pointer.
    per_torrent_state &torrentState(std::uint32_t id)
    {
        if (id >= torrents.size())
            torrents.resize(static_cast<std::size_t>(id) + 1);
        auto &slot = torrents[id];
        if (!slot)
            slot = std::make_unique<per_torrent_state>();
        return *slot;
    }

    per_torrent_state *findTorrent(std::uint32_t id) noexcept
    {
        return ((id < torrents.size()) && torrents[id]) ? torrents[id].get() : nullptr;
    }

    const per_torrent_state *findTorrent(std::uint32_t id) const noexcept
    {
        return ((id < torrents.size()) && torrents[id]) ? torrents[id].get() : nullptr;
    }

    std::atomic<subscription_data *> subscription = new subscription_data();

    // Snapshots replaced by a newer refresh, kept alive for the whole process
    // and freed in the destructor so they are never freed on a thread that could
    // still be walking them. Written only on the app thread; the network thread
    // never touches this vector.
    std::vector<subscription_data *> m_retiredSnapshots;

    ~behavior_state()
    {
        for (subscription_data *snap : m_retiredSnapshots)
            delete snap;
        m_retiredSnapshots.clear();
        delete subscription.load(std::memory_order_acquire);
    }
};

// ---- per-torrent shared state --------------------------------------------
// A magnet / URL-seed torrent is attached before its metadata arrives, when
// torrent_file() is null and neither the size nor the private flag is known.
// Every peer plugin of one torrent shares a single instance so that a peer
// which connected before the metadata arrived is not frozen at size 0 (and the
// torrent cannot dodge the private-tracker exemption). All callbacks run on the
// single libtorrent network thread, so this is plain, non-atomic data.
struct torrent_context
{
    explicit torrent_context(lt::torrent_handle h)
        : handle(std::move(h))
    {
    }

    // Resolve metadata at most once. After the first successful resolution the
    // hot per-tick path is a single boolean test with no handle lookup and no
    // lock, and the torrent handle is dropped (the torrent's lifetime is already
    // pinned by its plugin). Until then (magnet, metadata pending) it re-probes
    // torrent_file().
    void ensureResolved()
    {
        if (sizeKnown)                          // steady-state: one bool read
            return;
        const auto tf = handle.torrent_file();
        if (!tf)                                // magnet: metadata still pending
            return;
        disabled = tf->priv();                  // never police private trackers
        size = tf->total_size();
        // Precompute everything the per-tick path derives from `size`, once:
        // the reciprocal turns the per-tick progress division into a multiply,
        // `allowedExcess` folds the max()+threshold math of the excess check.
        // Two gates: `enforce` (sizeKnown && !disabled) lets a torrent take part
        // in membership + self-ban enforcement, including small torrents whose
        // subscription/multi-dial bans must still apply; `detect` adds the
        // minimum-size gate and only guards the PCB progress math in
        // runDetections(). Splitting them preserves the pre-optimization
        // behavior where small torrents skipped detections but still enforced
        // bans.
        invSize = (size > 0) ? (1.0 / static_cast<double>(size)) : 0.0;
        allowedExcess = static_cast<std::int64_t>(
            static_cast<double>(std::max(size, kMinTorrentSizeBytes)) * kExcessiveThreshold);
        enforce = !disabled;
        detect = enforce && (size >= kMinTorrentSizeBytes);
        sizeKnown = true;
        handle = {};                            // resolved: release the handle
    }

    lt::torrent_handle handle;
    std::int64_t size = 0;
    std::int64_t allowedExcess = 0;   // size-derived excess-download ceiling
    double invSize = 0.0;             // 1.0 / size, for division-free progress
    bool sizeKnown = false;
    bool disabled = false;
    bool enforce = false;             // == sizeKnown && !disabled (sizeKnown 于本函数末尾置位)
    bool detect = false;              // enforce && size >= minimum: run PCB detections
};

// ---- peer plugin ------------------------------------------------
class peer_behavior_plugin final : public lt::peer_plugin
{
public:
    peer_behavior_plugin(std::shared_ptr<behavior_state> state, std::uint32_t torrentId
                         , std::shared_ptr<torrent_context> ctx, lt::peer_connection_handle ph)
        : m_state(std::move(state))
        , m_torrentId(torrentId)
        , m_ctx(std::move(ctx))
        , m_peer(ph)
    {
    }

    void tick() override
    {
        if (!m_attached || !m_state || m_ignored)
            return;

        // Metadata resolution belongs to the torrent plugin (its tick(), with
        // new_connection() as an immediate fallback); this peer only reads the
        // shared m_ctx. While a magnet's metadata is still pending - or forever
        // if it never arrives - the whole plugin sleeps, so no ban, membership
        // or detection logic runs in any metadata window. A private magnet is
        // never policed, and a never-resolving magnet costs no per-peer work
        // each second. `enforce` folds the metadata/private gates into a single
        // boolean test; small torrents stay enforced (membership + self-ban)
        // and only skip the PCB progress math via `detect` in runDetections().
        if (!m_ctx->enforce)
            return;

        // Steady state (the overwhelmingly common path): the address was
        // classified once at connect time and cannot change on a live link, so
        // the self-ban check needs no peer_info at all. A peer banned by
        // somebody else's multi-dial/PCB decision disconnects here without
        // paying for a get_peer_info it would never use.
        if (m_registered)
        {
            if (isBanned(m_identity))
            {
                disconnectNow();
                return;
            }
            if (!m_ctx->detect)          // 小种子：已完成分类且无 PCB 检测需求，跳过 peer_info
                return;
            lt::peer_info info;
            m_peer.get_peer_info(info);
            runDetections(info, m_identity);
            return;
        }

        lt::peer_info info;
        m_peer.get_peer_info(info);

        // Classify exactly once per connection: the address cannot change on a
        // live link, so reclassifying (and re-hashing a v6 address) every tick
        // would be pure waste. registerMembership is idempotent.
        const peer_identity ident = classify_peer(info.ip.address());
        if (!ident.ok)
        {
            m_ignored = true; // I2P / non-IP connection, ignore (address is immutable)
            return;
        }

        registerMembership(ident);

        if (isBanned(ident))
        {
            disconnectNow();
            return;
        }

        runDetections(info, ident);
    }

    void on_disconnect(const boost::system::error_code &) override
    {
        if (!m_state || !m_registered)
            return;
        // find() only: disconnecting must never re-create maps that were
        // pruned after their last member left, otherwise the tables would grow
        // without bound over a long session. Drained subnet maps are pruned so
        // future lookups stay small; both are observably identical to keeping
        // empty maps around.
        if (per_torrent_state *tor = m_state->findTorrent(m_torrentId))
        {
            if (m_identity.v4)
            {
                const auto sit = tor->subnetsV4.find(m_identity.subnet24);
                if (sit != tor->subnetsV4.end())
                {
                    auto it = sit->second.find(m_identity.host);
                    if (it != sit->second.end())
                    {
                        if (it->second <= 1)
                            sit->second.erase(it);
                        else
                            --it->second;
                    }
                    if (sit->second.empty())
                        tor->subnetsV4.erase(sit);
                }
            }
            else
            {
                const auto sit = tor->subnetsV6.find(m_identity.v6mult);
                if (sit != tor->subnetsV6.end())
                {
                    auto it = sit->second.find(m_identity.v6id);
                    if (it != sit->second.end())
                    {
                        if (it->second <= 1)
                            sit->second.erase(it);
                        else
                            --it->second;
                    }
                    if (sit->second.empty())
                        tor->subnetsV6.erase(sit);
                }
            }
        }
        m_registered = false;
        m_attached = false;
    }

private:
    void registerMembership(const peer_identity &ident)
    {
        if (m_registered)
            return;

        m_identity = ident;
        m_registered = true;

        // A subnet's membership only changes at connect/disconnect, so the
        // multi-dial check runs exactly once - right after incrementing - which
        // is equivalent to checking on every tick but costs one map probe per
        // connection instead of several per second. The increment and the
        // distinct-IP size check share a single lookup of the subnet map.
        // Multi-dial blocking: too many distinct IPs of one subnet attached to
        // the same torrent means one user hogging connections -> nuke it.
        per_torrent_state &tor = m_state->torrentState(m_torrentId);
        if (ident.v4)
        {
            auto &subnetMap = tor.subnetsV4[ident.subnet24];
            ++subnetMap[ident.host];
            if (subnetMap.size() > kTolerateV4)
                banSubnetV4(ident.subnet24);
        }
        else
        {
            auto &subnetMap = tor.subnetsV6[ident.v6mult];
            ++subnetMap[ident.v6id];
            if (subnetMap.size() > kTolerateV6)
                banSubnetV6(ident.v6mult);
        }
    }

    // Stable per-connection anchor into the cross-reconnect PCB tracking map.
    // The (torrentId, ip-group) pair never changes for this plugin and nothing
    // ever erases from `track`, so resolve the entry once and reuse the pointer
    // on every tick instead of probing the map each time.
    peer_track &tracked(const peer_identity &ident)
    {
        if (!m_trk)
            m_trk = &m_state->torrentState(m_torrentId).track[ident.groupKey()];
        return *m_trk;
    }

    bool isBanned(const peer_identity &ident) const
    {
        if (ident.v4)
        {
            if (m_state->bannedExact.count(ident.host)
                    || m_state->bannedSubnet30.count(ident.subnet30)
                    || m_state->bannedSubnet24.count(ident.subnet24))
                return true;
            const subscription_data *sub = m_state->subscription.load(std::memory_order_acquire);
            return sub && !sub->trieV4.empty() && sub->trieV4.contains(ident.bytes, 32);  // v4 prefixes are at most /32
        }
        if (m_state->bannedSubnet56.count(ident.v6mult)
            || m_state->bannedSubnet48.count(ident.v6arb))
            return true;
        const subscription_data *sub = m_state->subscription.load(std::memory_order_acquire);
        return sub && !sub->trieV6.empty() && sub->trieV6.contains(ident.bytes, 128);
    }

    void runDetections(const lt::peer_info &info, const peer_identity &ident)
    {
        // Small torrents (< kMinTorrentSizeBytes) skip the progress math but
        // still take part in membership + self-ban enforcement in tick().
        if (!m_ctx->detect)
            return;
        const std::int64_t size = m_ctx->size;

        // PBH hands peers still in the handshake the "handshaking" pass; their
        // reported progress (0) is not yet trustworthy.
        if (info.flags & lt::peer_info::handshake)
            return;

        // The steady clock is only sampled when a suspicion threshold is
        // actually crossed: healthy peers (the common case) never pay for it.
        // A dedicated sampled flag (not a now==0 sentinel) keeps single-sample
        // semantics even if the clock ever reports 0.
        std::int64_t now = 0;
        bool nowSampled = false;
        const auto nowLazy = [&]() -> std::int64_t
        {
            if (!nowSampled)
            {
                now = nowMs();
                nowSampled = true;
            }
            return now;
        };

        const float progress = std::clamp(info.progress, 0.0f, 1.0f);
        peer_track &trk = tracked(ident);

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

        // Capture the previous non-zero report BEFORE overwriting it with this
        // tick's value (PBH "finally" semantics): record every (non-zero)
        // reported progress so the rewind check below can see a drop that a
        // healthy peer never shows. Storing every tick is what lets rewind also
        // catch a peer that resets to a low progress even when we have uploaded
        // very little to it.
        const float lastReported = trk.lastReportProgress;
        if (progress != 0.0f)
            trk.lastReportProgress = progress;

        // ---- (1) Excess download (PBH excessiveClient) -----------------------
        // Uses the cumulative upload count against the precomputed ceiling
        // (floored at max(torrentSize, minimumSize) x threshold, exactly like
        // PBH): a single integer compare on this path.
        if ((trk.statusUploaded > size) && (trk.statusUploaded > m_ctx->allowedExcess))
        {
            clearSuspicion(trk);
            banExact(ident, "Excess download");
            return;
        }

        if (!uploading)          // PBH early pass: no uploads -> no progress judgement
            return;

        // Reciprocal multiply instead of a division: identical within a unit in
        // the last place, far below the 2% suspicion threshold.
        const double computedProgress = static_cast<double>(trk.statusUploaded) * m_ctx->invSize;

        // ---- (2) Under-reported progress (PBH differenceTest) ---------------
        // Only possible when our computed share exceeds the progress it reports.
        // The confirmation window absorbs a brief transient (a fast peer's
        // reported progress catching up to our upload count) while a sustained
        // under-report eventually exceeds the window and is banned.
        if (computedProgress > progress)
        {
            if ((computedProgress - progress) > kMaxProgressDiff)
            {
                if (confirmSuspicion(trk, nowLazy()))
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
        }
        else
        {
            // Reported >= computed: as far as the difference is concerned the
            // peer is advancing normally. A rewind that also trips below is
            // judged independently on the next block.
            clearSuspicion(trk);
        }

        // ---- (3) Progress rewind (PBH progressRewind) ----------------------
        // Independent of the difference test so a peer that resets to a low
        // progress - even with little uploaded on our side - is still flagged.
        // progress>0 means it has already sent its (low) bitfield, i.e. the drop
        // is a deliberate reset -> ban immediately. progress==0 (a reconnecting
        // seeder before its bitfield) waits out the confirmation window instead.
        if ((kRewindMaxDiff > 0.0f) && (lastReported >= 0.0f))
        {
            const double rewind = static_cast<double>(lastReported) - progress;
            if (rewind > kRewindMaxDiff)
            {
                if ((progress > 0.0f) || confirmSuspicion(trk, nowLazy()))
                {
                    clearSuspicion(trk);
                    banExact(ident, "Progress rewind");
                    return;
                }
            }
        }
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
            // Single-probe insert: the return flag replaces count()+insert().
            newlyBanned = m_state->bannedExact.insert(ident.host).second;
            // auto range-ban: also cover the neighbouring /30 (v4)
            newlyBanned = m_state->bannedSubnet30.insert(ident.subnet30).second || newlyBanned;
        }
        else
        {
            // auto range-ban: also cover the neighbouring /48 (v6)
            newlyBanned = m_state->bannedSubnet48.insert(ident.v6arb).second;
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
        if (!m_state->bannedSubnet24.insert(subnet24).second)
            return;

        // find() only: the subnet map is guaranteed present (we are registered
        // in it), and a lookup must never re-create a pruned entry.
        if (const per_torrent_state *tor = m_state->findTorrent(m_torrentId))
        {
            const auto sit = tor->subnetsV4.find(subnet24);
            if (sit != tor->subnetsV4.end())
            {
                for (const auto &kv : sit->second)
                {
                    m_state->bannedExact.insert(kv.first);
                    m_state->bannedSubnet30.insert(kv.first & 0xFFFFFFFCu);
                }
            }
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

    void banSubnetV6(std::uint64_t subnet56)
    {
        if (!m_state->bannedSubnet56.insert(subnet56).second)
            return;

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
    std::shared_ptr<torrent_context> m_ctx;
    const std::uint32_t m_torrentId;
    lt::peer_connection_handle m_peer;
    peer_identity m_identity;
    std::int64_t m_lastUpload = 0;   // last observed total_upload on this connection
    peer_track *m_trk = nullptr;     // cached PCB-track slot for this connection
    bool m_hasPrevTotal = false;     // whether m_lastUpload is meaningful yet
    bool m_registered = false;
    bool m_ignored = false;          // non-IP (I2P) connection, classified once
    bool m_attached = true;
};

// ---- torrent plugin ---------------------------------------------
class peer_behavior_torrent_plugin final : public lt::torrent_plugin
{
public:
    peer_behavior_torrent_plugin(std::shared_ptr<behavior_state> state, std::uint32_t torrentId
                                 , std::shared_ptr<torrent_context> ctx)
        : m_state(std::move(state))
        , m_torrentId(torrentId)
        , m_ctx(std::move(ctx))
    {
    }

    std::shared_ptr<lt::peer_plugin> new_connection(lt::peer_connection_handle const &ph) override
    {
        // Immediate fallback so a connection (e.g. on a torrent whose metadata
        // is already known, or one that arrived right before this connect)
        // resolves without waiting for the next tick. Idempotent and cheap once
        // sizeKnown is set.
        m_ctx->ensureResolved();
        return std::make_shared<peer_behavior_plugin>(m_state, m_torrentId, m_ctx, ph);
    }

    // Central resolution point: one per-torrent re-probe per second (instead of
    // one per peer) while a magnet's metadata is pending. Once resolved this is
    // just a single bool test and the shared handle is already released.
    void tick() override
    {
        m_ctx->ensureResolved();
    }

private:
    std::shared_ptr<behavior_state> m_state;
    const std::uint32_t m_torrentId;
    std::shared_ptr<torrent_context> m_ctx;
};

// ---- session plugin ---------------------------------------------
class peer_behavior_monitor final : public lt::plugin
{
public:
    peer_behavior_monitor()
        : m_state(std::make_shared<behavior_state>())
    {
        // Last-known bans (incl. last subscription) first, then refresh the
        // network IP-set rules from the remote source. If the fetch fails we
        // keep whatever the cache provided.
        loadBanCache();
        fetchSubscription();
    }

    ~peer_behavior_monitor() override
    {
        // Runs from SessionImpl::~SessionImpl while the lt::session and its
        // network threads are already being torn down (after pause() and resume
        // data save), so a single synchronous disk write here is safe and sees
        // the final ban state.
        saveBanCache();
    }

    std::shared_ptr<lt::torrent_plugin> new_torrent(lt::torrent_handle const &th, client_data) override
    {
        // Private torrents whose metadata is already known are skipped outright.
        // A magnet / URL-seed add has no torrent_file() yet, so its privateness
        // and size are unknowable here; we attach a shared torrent_context and
        // resolve them lazily (once) on the network thread. That covers magnets
        // / RSS magnet URLs and still keeps the private-tracker exemption intact
        // as soon as the metadata lands.
        const auto tf = th.torrent_file();
        if (tf && tf->priv())
            return nullptr;
        auto ctx = std::make_shared<torrent_context>(th);
        if (tf)
            ctx->ensureResolved();   // fully-known torrent: no lazy work later
        return std::make_shared<peer_behavior_torrent_plugin>(m_state, m_nextId++, std::move(ctx));
    }

private:
    // Ban persistence (read once at startup; written once at orderly shutdown).
    // Plain text, one <kind> <ip> per line:
    //   v4   203.0.113.5   (exact IPv4 host)
    //   s30  203.0.113.4   (banned /30)
    //   s24  203.0.113.0   (banned /24, multi-dial)
    //   v6a  2001:db8::   (banned /48, auto range-ban; host bits already zeroed)
    //   v6m  2001:db8::   (banned /56, multi-dial; host bits already zeroed)
    void loadBanCache()
    {
        const Path dir = specialFolderLocation(SpecialFolder::Data);
        if (dir.isEmpty())
            return;

        const Path file = dir / Path(QStringLiteral("behavior_ban_cache.txt"));
        QFile in(file.toString());
        if (!in.open(QIODevice::ReadOnly))
            return;

        QTextStream ts(&in);

        // The constructor is the only mutator of the (shared) default snapshot:
        // it runs before the torrent/network thread exists and before the
        // background refresh can store anything, so filling the snapshot's
        // tries/mirrors here is safe. The refresh later replaces it wholesale
        // via an atomic pointer store.
        subscription_data *sub = m_state->subscription.load();
        while (!ts.atEnd())
        {
            const QStringList parts = ts.readLine().split(QLatin1Char(' '));
            if ((parts.size() < 2) || parts[1].isEmpty())
                continue;

            peer_identity ident;
            try
            {
                ident = classify_peer(lt::make_address(parts[1].toStdString()));
                if (!ident.ok)
                    continue;
            }
            catch (const std::exception &)
            {
                continue;
            }

            if ((parts[0] == QLatin1String("v4")) && ident.v4)
                m_state->bannedExact.insert(ident.host);
            else if ((parts[0] == QLatin1String("s30")) && ident.v4)
                m_state->bannedSubnet30.insert(ident.subnet30);
            else if ((parts[0] == QLatin1String("s24")) && ident.v4)
                m_state->bannedSubnet24.insert(ident.subnet24);
            else if ((parts[0] == QLatin1String("v6a")) || (parts[0] == QLatin1String("v6m")))
            {
                // Guard against a malformed "v6x <ipv4>" line: classifying an
                // IPv4 would leave the prefix keys at 0 and ban all of IPv6.
                if (!ident.v4)
                {
                    // v6a = ARB /48, v6m = multi-dial /56.
                    if (parts[0] == QLatin1String("v6m"))
                        m_state->bannedSubnet56.insert(ident.v6mult);
                    else
                        m_state->bannedSubnet48.insert(ident.v6arb);
                }
            }
            else if (parts[0] == QLatin1String("c4"))
            {
                subnet_v4 s4;
                subnet_v6 s6;
                if (parseCIDR(parts[1], s4, s6) == 1)
                {
                    sub->v4.push_back(s4);
                    sub->trieV4.insert(v4HostToBytes(s4.net), s4.prefix);
                }
            }
            else if (parts[0] == QLatin1String("c6"))
            {
                subnet_v4 s4;
                subnet_v6 s6;
                if (parseCIDR(parts[1], s4, s6) == 2)
                {
                    sub->v6.push_back(s6);
                    sub->trieV6.insert(s6.net, s6.prefix);
                }
            }
        }
    }

    void saveBanCache()
    {
        const Path dir = specialFolderLocation(SpecialFolder::Data);
        if (dir.isEmpty())
            return;

        const Path file = dir / Path(QStringLiteral("behavior_ban_cache.txt"));
        QFile out(file.toString());
        if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate))
            return;

        QTextStream ts(&out);
        for (const std::uint64_t host : m_state->bannedExact)
            ts << QStringLiteral("v4 ") << formatIPv4(static_cast<std::uint32_t>(host & 0xFFFFFFFFu)) << '\n';
        for (const std::uint32_t subnet : m_state->bannedSubnet30)
            ts << QStringLiteral("s30 ") << formatIPv4(subnet) << '\n';
        for (const std::uint32_t subnet : m_state->bannedSubnet24)
            ts << QStringLiteral("s24 ") << formatIPv4(subnet) << '\n';
        // v6a = /48 (auto range-ban), v6m = /56 (multi-dial). The stored network
        // string already has its host bits zeroed, so its prefix is self-evident.
        for (const std::uint64_t sub : m_state->bannedSubnet48)
            ts << QStringLiteral("v6a ") << QString::fromStdString(lt::address_v6(v6HiToBytes(sub)).to_string()) << '\n';
        for (const std::uint64_t sub : m_state->bannedSubnet56)
            ts << QStringLiteral("v6m ") << QString::fromStdString(lt::address_v6(v6HiToBytes(sub)).to_string()) << '\n';

        const subscription_data *sub = m_state->subscription.load(std::memory_order_acquire);
        for (const subnet_v4 &s : sub->v4)
            ts << QStringLiteral("c4 ") << formatIPv4(s.net) << QLatin1Char('/') << s.prefix << '\n';
        for (const subnet_v6 &s : sub->v6)
            ts << QStringLiteral("c6 ") << QString::fromStdString(lt::address_v6(s.net).to_string())
               << QLatin1Char('/') << static_cast<int>(s.prefix) << '\n';
    }

    // Kick off an asynchronous fetch of the network IP-set rules (PBH-BTN/BCR
    // combined list) through the app-wide Net::DownloadManager (handles proxy,
    // SSL, timeouts - the same path the app uses for tracker/rules updates).
    // Returns immediately so startup is never blocked; until a successful
    // refresh the snapshot loaded from cache by loadBanCache() stays in effect.
    // The finished callback is anchored to m_ctx (auto-disconnected if this
    // monitor is torn down while a download is still in flight) and captures
    // m_state by value, so the shared state is kept alive regardless of this
    // monitor's lifetime. It parses into a fresh snapshot, applies the
    // empty-result guard, and only then publishes it via an atomic pointer
    // exchange that the libtorrent thread reads with an acquire load. The
    // replaced snapshot is retired (kept alive) rather than freed, so a reader
    // still walking it never races a deletion; reclamation happens at shutdown.
    void fetchSubscription()
    {
        Net::DownloadManager *const mgr = Net::DownloadManager::instance();
        if (!mgr)
            return;

        const std::shared_ptr<behavior_state> state = m_state;
        Net::DownloadHandler *const handler = mgr->download(
            Net::DownloadRequest(QStringLiteral("https://bcr.pbh-btn.com/combine/all.txt"))
                .limit(4 * 1024 * 1024),
            false);
        QObject::connect(handler, &Net::DownloadHandler::finished, &m_ctx,
            [state](const Net::DownloadResult &res) {
                if (res.status != Net::DownloadStatus::Success)
                {
                    LogMsg(QStringLiteral("BehaviorAntiLeech: subscription fetch failed (%1), keeping cached rules")
                               .arg(res.errorString));
                    return;
                }

                auto fresh = std::make_unique<subscription_data>();
                const std::size_t parsed = parseSubscriptionBody(res.data, *fresh);

                if (parsed >= kMinSubscriptionRules)
                {
                    const std::size_t v4Count = fresh->v4.size();
                    const std::size_t v6Count = fresh->v6.size();
                    subscription_data *old = state->subscription.exchange(fresh.release(), std::memory_order_acq_rel);
                    if (old)
                        state->m_retiredSnapshots.push_back(old);
                    LogMsg(QStringLiteral("BehaviorAntiLeech: subscription refresh applied (%1 v4, %2 v6 CIDRs)")
                               .arg(v4Count).arg(v6Count));
                }
                else
                {
                    // Malformed/truncated body (e.g. a rate-limit or captive
                    // page): keep the last known-good cache. `fresh` is
                    // reclaimed by the unique_ptr on this path.
                    LogMsg(QStringLiteral("BehaviorAntiLeech: subscription refresh rejected (%1 rules < %2), keeping cached rules")
                               .arg(parsed).arg(kMinSubscriptionRules));
                }
            });
    }

    // Parse a downloaded subscription body into `out`. Returns the number of
    // CIDRs successfully parsed; the empty-result guard lives in
    // fetchSubscription. Parses into a throwaway snapshot rather than the live
    // state, so a rejected body never disturbs the published snapshot.
    static std::size_t parseSubscriptionBody(const QByteArray &body, subscription_data &out)
    {
        std::size_t parsed = 0;
        // Single in-place pass over the raw bytes: no whole-buffer QString copy,
        // no BOM-removal rewrite, and no QStringList of per-line QStrings. Blank
        // and '#' lines are skipped on the raw bytes; only the lines that need
        // parsing are materialized into a small per-line QString.
        const char *p = body.constData();
        const int len = body.size();
        int lineStart = ((len >= 3)
            && (static_cast<unsigned char>(p[0]) == 0xEF)
            && (static_cast<unsigned char>(p[1]) == 0xBB)
            && (static_cast<unsigned char>(p[2]) == 0xBF)) ? 3 : 0; // strip UTF-8 BOM
        while (lineStart < len)
        {
            int eol = lineStart;
            while (eol < len && p[eol] != '\n')
                ++eol;
            int b = lineStart;
            int e = eol;
            if (e > b && p[e - 1] == '\r')         // drop trailing CR
                --e;
            while (b < e && (p[b] == ' ' || p[b] == '\t'))
                ++b;
            while (e > b && (p[e - 1] == ' ' || p[e - 1] == '\t'))
                --e;
            if (e > b && p[b] != '#')   // skip blanks and comment lines
            {
                const QString line = QString::fromUtf8(p + b, e - b);
                subnet_v4 s4;
                subnet_v6 s6;
                const int kind = parseCIDR(line, s4, s6);
                if (kind == 1)
                {
                    out.v4.push_back(s4);
                    out.trieV4.insert(v4HostToBytes(s4.net), s4.prefix);
                    ++parsed;
                }
                else if (kind == 2)
                {
                    out.v6.push_back(s6);
                    out.trieV6.insert(s6.net, s6.prefix);
                    ++parsed;
                }
            }
            lineStart = eol + 1;
        }
        return parsed;
    }

private:
    std::shared_ptr<behavior_state> m_state;
    std::uint32_t m_nextId = 0;

    // Context/anchor for the Net::DownloadManager callback. It is not a QObject
    // itself (the plugin derives from lt::plugin), so this member gives the
    // connect() a QObject context: the slot runs on the main thread and is
    // auto-disconnected when this monitor is destroyed, and it is torn down
    // before m_state in the destructor order. qBittorrent compiles with
    // QT_NO_CONTEXTLESS_CONNECT, so a context is mandatory.
    QObject m_ctx;
};

} // namespace