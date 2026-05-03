#pragma once

// Reverse-route table populated from observed flood traffic at repeaters.
// See docs/superpowers/specs/2026-04-29-meshcore-routing-design.md §5.1.
//
// Host-test compatible: no Arduino includes. Constants come from MeshCore.h.

#include <stdint.h>
#include <string.h>
#include <MeshCore.h>

#ifndef ROUTE_CACHE_CAPACITY
  #define ROUTE_CACHE_CAPACITY  256
#endif

#define ROUTE_CACHE_PATH_MAX   16   // max hops per cached path; matches alt-path slot size

struct RouteEntry {
  uint8_t  dest_pubkey[PUB_KEY_SIZE];   // 32 bytes — full pubkey for unambiguous match
  uint8_t  hop_count;                   // 0..ROUTE_CACHE_PATH_MAX
  uint8_t  path[ROUTE_CACHE_PATH_MAX];  // forwarder hashes; entries with longer paths NOT stored
  uint8_t  _pad1;                       // align int16 below
  int16_t  last_snr_x4;                 // SNR×4 of last packet observed via this exact path
                                        // (int16 so SNR > +31 dB or < -32 dB doesn't overflow;
                                        // real LoRa links span ~-20 .. +60 dB)
  uint16_t n_seen;                      // observation count, capped at 65535
  uint16_t _pad2;                       // align uint32 below
  uint32_t last_seen_secs;              // RTC timestamp of last observation
  uint32_t first_seen_secs;             // RTC timestamp of first observation
};
static_assert(sizeof(RouteEntry) == 64, "RouteEntry must be 64 bytes for clean array math");

class RouteCache {
public:
  RouteCache(uint32_t ttl_secs = 1800);   // default TTL = 30 min

  // Observation hook. Inserts or refreshes the entry for (dest_pubkey, path).
  // path is the path THIS NODE would use to reach dest (i.e., reversed wire path).
  // snr_x4 is int16_t to accommodate the full LoRa SNR range (~-20..+60 dB);
  // int8_t would overflow on strong links (e.g. 50 dB → snr_x4=200 wraps to -56).
  void observe(const uint8_t* dest_pubkey, const uint8_t* path, uint8_t hop_count,
               int16_t snr_x4, uint32_t now_secs);

  // Lookup the best cached route to dest_hash.
  // hash_size is PATH_HASH_SIZE (typically 1).
  // exclude_path/exclude_path_len optionally filter out a specific path the caller already tried.
  // Returns up to max_results entries sorted by score descending. Returns count actually written.
  int lookup(uint8_t dest_hash, uint8_t hash_size,
             const uint8_t* exclude_path, uint8_t exclude_path_len,
             RouteEntry* out_results, int max_results, uint32_t now_secs);

  // Pure scoring function (does NOT consume cache state). Higher = better.
  static int32_t computeScore(const RouteEntry& e, uint32_t now_secs);

  // Drop entries older than ttl_secs (relative to now_secs).
  void prune(uint32_t now_secs);

  // Diagnostic / config.
  void   clear();
  int    size() const { return _used; }
  void   setTTL(uint32_t secs) { _ttl_secs = secs; }
  uint32_t getTTL() const { return _ttl_secs; }
  bool   getEntry(int idx, RouteEntry& out) const;

private:
  RouteEntry _entries[ROUTE_CACHE_CAPACITY];
  int        _used;          // count of valid entries (may be < CAPACITY)
  uint32_t   _ttl_secs;

  // Find entry matching (dest_pubkey, path, hop_count); returns index or -1.
  int findExact(const uint8_t* dest_pubkey, const uint8_t* path, uint8_t hop_count) const;

  // Find oldest (lowest last_seen_secs) entry — for LRU eviction. Returns index 0..CAPACITY-1.
  int findOldest() const;
};
