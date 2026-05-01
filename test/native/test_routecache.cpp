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

int main() {
    std::printf("test_routecache: %d test(s) registered\n", tests_run);
    if (tests_failed) {
        std::printf("FAIL: %d failure(s)\n", tests_failed);
        return 1;
    }
    return 0;
}
