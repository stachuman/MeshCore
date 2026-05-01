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

int main() {
    std::printf("test_routecache: %d test(s) registered\n", tests_run);
    if (tests_failed) {
        std::printf("FAIL: %d failure(s)\n", tests_failed);
        return 1;
    }
    return 0;
}
