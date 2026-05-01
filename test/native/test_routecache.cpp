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

int main() {
    std::printf("test_routecache: %d test(s) registered\n", tests_run);
    if (tests_failed) {
        std::printf("FAIL: %d failure(s)\n", tests_failed);
        return 1;
    }
    return 0;
}
