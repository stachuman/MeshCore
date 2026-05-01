#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "helpers/RouteCache.h"

static int tests_run = 0;
static int tests_failed = 0;

#define TEST(name) static void name(); \
    struct name##_runner { name##_runner() { ++tests_run; std::printf("  [test] " #name " ... "); name(); std::printf("ok\n"); } } name##_inst; \
    static void name()

TEST(test_construct_default) {
    RouteCache cache;
    assert(cache.size() == 0);
}

// Helper: build a fixed pubkey filled with a single byte for tests.
static void fillKey(uint8_t* key, uint8_t fill) {
    memset(key, fill, PUB_KEY_SIZE);
}

TEST(test_observe_inserts_first_entry) {
    RouteCache cache;
    uint8_t key[PUB_KEY_SIZE];
    fillKey(key, 0xAA);
    uint8_t path[3] = { 0x10, 0x20, 0x30 };

    cache.observe(key, path, 3, /*snr_x4*/ 12, /*now_secs*/ 1000);

    assert(cache.size() == 1);
    RouteEntry e;
    assert(cache.getEntry(0, e));
    assert(memcmp(e.dest_pubkey, key, PUB_KEY_SIZE) == 0);
    assert(e.hop_count == 3);
    assert(e.path[0] == 0x10 && e.path[1] == 0x20 && e.path[2] == 0x30);
    assert(e.last_snr_x4 == 12);
    assert(e.n_seen == 1);
    assert(e.last_seen_secs == 1000);
    assert(e.first_seen_secs == 1000);
}

TEST(test_observe_updates_duplicate) {
    RouteCache cache;
    uint8_t key[PUB_KEY_SIZE]; fillKey(key, 0xAA);
    uint8_t path[2] = { 0x42, 0x99 };

    cache.observe(key, path, 2, 8, 1000);
    cache.observe(key, path, 2, 16, 1500);   // same key+path, fresher SNR

    assert(cache.size() == 1);   // not a new entry
    RouteEntry e;
    assert(cache.getEntry(0, e));
    assert(e.last_snr_x4 == 16);
    assert(e.n_seen == 2);
    assert(e.last_seen_secs == 1500);
    assert(e.first_seen_secs == 1000);   // unchanged
}

TEST(test_observe_different_path_creates_new_entry) {
    RouteCache cache;
    uint8_t key[PUB_KEY_SIZE]; fillKey(key, 0xAA);
    uint8_t path_a[2] = { 0x01, 0x02 };
    uint8_t path_b[2] = { 0x01, 0x03 };   // diff at last byte

    cache.observe(key, path_a, 2, 4, 1000);
    cache.observe(key, path_b, 2, 4, 1000);

    assert(cache.size() == 2);
}

TEST(test_observe_rejects_oversized_path) {
    RouteCache cache;
    uint8_t key[PUB_KEY_SIZE]; fillKey(key, 0xAA);
    uint8_t path[20] = {0};   // bigger than ROUTE_CACHE_PATH_MAX

    cache.observe(key, path, 20, 4, 1000);

    assert(cache.size() == 0);   // dropped silently — too long for storage
}

TEST(test_lookup_empty_cache) {
    RouteCache cache;
    RouteEntry results[4];
    int n = cache.lookup(/*dest_hash*/ 0xAA, /*hash_size*/ 1,
                          /*exclude*/ nullptr, 0, results, 4, /*now*/ 1000);
    assert(n == 0);
}

TEST(test_lookup_single_match) {
    RouteCache cache;
    uint8_t key[PUB_KEY_SIZE]; fillKey(key, 0xAA);
    uint8_t path[1] = { 0x55 };
    cache.observe(key, path, 1, 4, 1000);

    RouteEntry results[4];
    int n = cache.lookup(0xAA, 1, nullptr, 0, results, 4, 1000);
    assert(n == 1);
    assert(memcmp(results[0].dest_pubkey, key, PUB_KEY_SIZE) == 0);
    assert(results[0].path[0] == 0x55);
}

TEST(test_lookup_no_hash_match) {
    RouteCache cache;
    uint8_t key[PUB_KEY_SIZE]; fillKey(key, 0xAA);
    uint8_t path[1] = { 0x55 };
    cache.observe(key, path, 1, 4, 1000);

    RouteEntry results[4];
    int n = cache.lookup(/*dest_hash*/ 0xBB, 1, nullptr, 0, results, 4, 1000);
    assert(n == 0);
}

TEST(test_lookup_multi_match_orders_by_recency) {
    RouteCache cache;
    uint8_t key[PUB_KEY_SIZE]; fillKey(key, 0xAA);
    uint8_t path_a[2] = { 0x01, 0x02 };
    uint8_t path_b[2] = { 0x01, 0x03 };

    cache.observe(key, path_a, 2, 4, 1000);   // older
    cache.observe(key, path_b, 2, 4, 2000);   // newer

    RouteEntry results[4];
    int n = cache.lookup(0xAA, 1, nullptr, 0, results, 4, 2000);
    assert(n == 2);
    // With placeholder scoring (recency only), newer should be first.
    assert(results[0].last_seen_secs == 2000);
    assert(results[1].last_seen_secs == 1000);
}

TEST(test_lookup_respects_max_results) {
    RouteCache cache;
    uint8_t key[PUB_KEY_SIZE]; fillKey(key, 0xAA);
    for (int i = 0; i < 5; i++) {
        uint8_t path[1] = { (uint8_t)i };
        cache.observe(key, path, 1, 4, 1000 + i);
    }

    RouteEntry results[2];
    int n = cache.lookup(0xAA, 1, nullptr, 0, results, 2, 1100);
    assert(n == 2);
}

TEST(test_lookup_excludes_matching_path) {
    RouteCache cache;
    uint8_t key[PUB_KEY_SIZE]; fillKey(key, 0xAA);
    uint8_t path_a[2] = { 0x01, 0x02 };
    uint8_t path_b[2] = { 0x01, 0x03 };
    cache.observe(key, path_a, 2, 4, 1000);
    cache.observe(key, path_b, 2, 4, 2000);

    uint8_t exclude[2] = { 0x01, 0x03 };
    RouteEntry results[4];
    int n = cache.lookup(0xAA, 1, exclude, 2, results, 4, 2000);

    assert(n == 1);
    assert(results[0].path[1] == 0x02);   // path_a survived
}

TEST(test_lookup_exclude_no_match_returns_all) {
    RouteCache cache;
    uint8_t key[PUB_KEY_SIZE]; fillKey(key, 0xAA);
    uint8_t path_a[2] = { 0x01, 0x02 };
    cache.observe(key, path_a, 2, 4, 1000);

    uint8_t exclude_other[2] = { 0xFF, 0xFF };
    RouteEntry results[4];
    int n = cache.lookup(0xAA, 1, exclude_other, 2, results, 4, 1000);

    assert(n == 1);
}

TEST(test_lookup_exclude_different_length_no_match) {
    RouteCache cache;
    uint8_t key[PUB_KEY_SIZE]; fillKey(key, 0xAA);
    uint8_t path_a[2] = { 0x01, 0x02 };
    cache.observe(key, path_a, 2, 4, 1000);

    // Exclude has same first 2 bytes but length differs — should not match.
    uint8_t exclude_short[1] = { 0x01 };
    RouteEntry results[4];
    int n = cache.lookup(0xAA, 1, exclude_short, 1, results, 4, 1000);

    assert(n == 1);
}

// Helper: build an entry directly for score testing.
static RouteEntry mkEntry(int8_t snr_x4, uint8_t hop_count, uint16_t n_seen,
                          uint32_t last_seen_secs) {
    RouteEntry e{};
    e.last_snr_x4 = snr_x4;
    e.hop_count = hop_count;
    e.n_seen = n_seen;
    e.last_seen_secs = last_seen_secs;
    e.first_seen_secs = last_seen_secs;
    return e;
}

TEST(test_score_fresh_strong_short) {
    // SNR +10 dB → snr_x4=40, snr/4=10, +20 = 30 (clamped to 60).
    // Age 0 min → freshness 60.
    // 1 hop → -5.
    // n_seen=5 → +5.
    // Total: 30 + 60 - 5 + 5 = 90.
    RouteEntry e = mkEntry(/*snr_x4*/ 40, /*hops*/ 1, /*n_seen*/ 5, /*ts*/ 1000);
    int32_t s = RouteCache::computeScore(e, /*now*/ 1000);
    assert(s == 90);
}

TEST(test_score_old_entry_drops_freshness) {
    // SNR +10 dB → 30; freshness clamp(60 - 90 min, 0, 60) = 0; 1 hop -5; n_seen 1 +1.
    // Total: 30 + 0 - 5 + 1 = 26.
    RouteEntry e = mkEntry(40, 1, 1, 1000);
    int32_t s = RouteCache::computeScore(e, 1000 + 90 * 60);
    assert(s == 26);
}

TEST(test_score_negative_snr_clamps_at_zero) {
    // SNR -25 dB → snr_x4=-100, snr/4=-25, +20 = -5 → clamped to 0.
    // Fresh, 0 hops, n_seen=1 → 0 + 60 - 0 + 1 = 61.
    RouteEntry e = mkEntry(-100, 0, 1, 1000);
    int32_t s = RouteCache::computeScore(e, 1000);
    assert(s == 61);
}

TEST(test_score_long_path_can_go_negative) {
    // Strong SNR but 30-hop path: 30 + 60 - 5*30 + 1 = -59.
    RouteEntry e = mkEntry(40, 30, 1, 1000);
    int32_t s = RouteCache::computeScore(e, 1000);
    assert(s == -59);
}

TEST(test_score_n_seen_caps_at_10) {
    RouteEntry e1 = mkEntry(40, 1, 10, 1000);
    RouteEntry e2 = mkEntry(40, 1, 50, 1000);
    assert(RouteCache::computeScore(e1, 1000) == RouteCache::computeScore(e2, 1000));
}

TEST(test_prune_removes_expired) {
    RouteCache cache(/*ttl_secs*/ 100);
    uint8_t key[PUB_KEY_SIZE]; fillKey(key, 0xAA);
    uint8_t path[1] = { 0x01 };
    cache.observe(key, path, 1, 4, 1000);
    assert(cache.size() == 1);

    cache.prune(/*now*/ 1101);
    assert(cache.size() == 0);
}

TEST(test_prune_keeps_fresh) {
    RouteCache cache(/*ttl_secs*/ 100);
    uint8_t key[PUB_KEY_SIZE]; fillKey(key, 0xAA);
    uint8_t path[1] = { 0x01 };
    cache.observe(key, path, 1, 4, 1000);

    cache.prune(/*now*/ 1050);   // within TTL
    assert(cache.size() == 1);
}

TEST(test_prune_compacts_entries) {
    RouteCache cache(/*ttl_secs*/ 100);
    uint8_t key[PUB_KEY_SIZE]; fillKey(key, 0xAA);
    uint8_t p1[1] = { 0x01 };
    uint8_t p2[1] = { 0x02 };
    uint8_t p3[1] = { 0x03 };
    cache.observe(key, p1, 1, 4, 900);   // will expire
    cache.observe(key, p2, 1, 4, 1000);  // survives
    cache.observe(key, p3, 1, 4, 950);   // will expire

    cache.prune(/*now*/ 1080);   // ttl=100, so anything older than 980 expires
    assert(cache.size() == 1);
    RouteEntry e;
    assert(cache.getEntry(0, e));
    assert(e.path[0] == 0x02);   // only p2 survived; appears at index 0 after compaction
}

TEST(test_eviction_at_capacity) {
    RouteCache cache;
    // Fill cache to capacity, then add one more.
    for (int i = 0; i < ROUTE_CACHE_CAPACITY; i++) {
        uint8_t key[PUB_KEY_SIZE];
        memset(key, 0, PUB_KEY_SIZE);
        // Vary first 2 bytes to guarantee distinct keys.
        key[0] = (uint8_t)(i & 0xFF);
        key[1] = (uint8_t)((i >> 8) & 0xFF);
        uint8_t path[1] = { 0x00 };
        cache.observe(key, path, 1, 4, 1000 + i);   // i is the timestamp offset
    }
    assert(cache.size() == ROUTE_CACHE_CAPACITY);

    // First entry (timestamp 1000) is the LRU. Adding a new entry with a
    // distinctive marker should evict that one.
    uint8_t marker_key[PUB_KEY_SIZE];
    memset(marker_key, 0xFF, PUB_KEY_SIZE);
    uint8_t marker_path[1] = { 0xEE };
    cache.observe(marker_key, marker_path, 1, 4, /*now=*/ 5000);

    assert(cache.size() == ROUTE_CACHE_CAPACITY);   // still at cap, not over

    // Verify oldest got evicted: lookup with hash 0x00 (the LRU's first byte)
    // should NOT return an entry whose pubkey[0] == 0 AND last_seen_secs == 1000.
    bool found_old = false;
    for (int j = 0; j < cache.size(); j++) {
        RouteEntry e;
        cache.getEntry(j, e);
        if (e.dest_pubkey[0] == 0 && e.dest_pubkey[1] == 0 && e.last_seen_secs == 1000) {
            found_old = true; break;
        }
    }
    assert(!found_old);

    // Verify the new marker is present.
    bool found_marker = false;
    for (int j = 0; j < cache.size(); j++) {
        RouteEntry e;
        cache.getEntry(j, e);
        if (memcmp(e.dest_pubkey, marker_key, PUB_KEY_SIZE) == 0) {
            found_marker = true; break;
        }
    }
    assert(found_marker);
}

int main() {
    std::printf("test_routecache: %d test(s) registered\n", tests_run);
    if (tests_failed) {
        std::printf("FAIL: %d failure(s)\n", tests_failed);
        return 1;
    }
    return 0;
}
