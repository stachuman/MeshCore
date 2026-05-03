#include "RouteCache.h"

RouteCache::RouteCache(uint32_t ttl_secs) : _used(0), _ttl_secs(ttl_secs) {
  memset(_entries, 0, sizeof(_entries));
}

void RouteCache::observe(const uint8_t* dest_pubkey, const uint8_t* path,
                          uint8_t hop_count, int16_t snr_x4, uint32_t now_secs) {
  if (hop_count > ROUTE_CACHE_PATH_MAX) {
    return;  // path too long to store; silently drop
  }

  int existing = findExact(dest_pubkey, path, hop_count);
  if (existing >= 0) {
    RouteEntry& e = _entries[existing];
    e.last_snr_x4 = snr_x4;
    e.last_seen_secs = now_secs;
    if (e.n_seen < UINT16_MAX) e.n_seen++;
    return;
  }

  // New entry. Either append (have room) or evict oldest (LRU).
  int idx;
  if (_used < ROUTE_CACHE_CAPACITY) {
    idx = _used++;
  } else {
    idx = findOldest();
  }

  RouteEntry& e = _entries[idx];
  memcpy(e.dest_pubkey, dest_pubkey, PUB_KEY_SIZE);
  e.hop_count = hop_count;
  if (hop_count > 0) memcpy(e.path, path, hop_count);
  if (hop_count < ROUTE_CACHE_PATH_MAX) {
    memset(&e.path[hop_count], 0, ROUTE_CACHE_PATH_MAX - hop_count);
  }
  e._pad1 = 0;
  e.last_snr_x4 = snr_x4;
  e.n_seen = 1;
  e._pad2 = 0;
  e.first_seen_secs = now_secs;
  e.last_seen_secs = now_secs;
}

int RouteCache::lookup(uint8_t dest_hash, uint8_t hash_size,
                        const uint8_t* exclude_path, uint8_t exclude_path_len,
                        RouteEntry* out_results, int max_results, uint32_t now_secs) {
  if (max_results <= 0 || out_results == nullptr) return 0;

  // Two-pass: (1) collect candidate indexes, (2) sort by score and copy.
  int candidates[ROUTE_CACHE_CAPACITY];
  int n_cand = 0;

  for (int i = 0; i < _used; i++) {
    const RouteEntry& e = _entries[i];
    // Hash prefix match against destination
    if (memcmp(e.dest_pubkey, &dest_hash, hash_size) != 0) continue;

    // Skip explicitly excluded path
    if (exclude_path != nullptr && exclude_path_len > 0
        && e.hop_count == exclude_path_len
        && memcmp(e.path, exclude_path, exclude_path_len) == 0) {
      continue;
    }

    candidates[n_cand++] = i;
  }

  // Hash-prefix ambiguity gate: if the surviving candidates point to MULTIPLE
  // distinct destination pubkeys, the prefix doesn't uniquely identify a node
  // and confidently returning any one of them risks routing the caller's traffic
  // to the wrong destination (silent message loss). Refuse to answer; the caller
  // will fall through to flood, which uses the real network paths.
  //
  // Caveat: legitimate multi-path entries (same dest_pubkey, different path bytes)
  // are NOT ambiguous — distinctness is by full 32-byte dest_pubkey comparison.
  //
  // The PATH_REQ_FLAG_FULL_TARGET protocol mechanism lets a future caller pass
  // the full 32-byte pubkey when it really needs disambiguation; the responder
  // can then exact-match before answering. Phase 2 callers don't use it yet.
  if (n_cand >= 2) {
    const uint8_t* first_dest = _entries[candidates[0]].dest_pubkey;
    for (int k = 1; k < n_cand; k++) {
      if (memcmp(first_dest, _entries[candidates[k]].dest_pubkey, PUB_KEY_SIZE) != 0) {
        return 0;  // ambiguous — stay silent
      }
    }
  }

  // Selection sort by score descending.
  int written = 0;
  while (written < max_results && written < n_cand) {
    int best_pos = written;
    int32_t best_score = computeScore(_entries[candidates[written]], now_secs);
    for (int j = written + 1; j < n_cand; j++) {
      int32_t s = computeScore(_entries[candidates[j]], now_secs);
      if (s > best_score) {
        best_score = s;
        best_pos = j;
      }
    }
    if (best_pos != written) {
      int tmp = candidates[written];
      candidates[written] = candidates[best_pos];
      candidates[best_pos] = tmp;
    }
    out_results[written] = _entries[candidates[written]];
    written++;
  }

  return written;
}

int32_t RouteCache::computeScore(const RouteEntry& e, uint32_t now_secs) {
  // SNR contribution: clamp(snr_dB + 20, 0, 60)
  int32_t snr_dB = (int32_t)e.last_snr_x4 / 4;
  int32_t snr_term = snr_dB + 20;
  if (snr_term < 0) snr_term = 0;
  if (snr_term > 60) snr_term = 60;

  // Freshness: clamp(60 - age_minutes, 0, 60)
  int32_t age_minutes = (now_secs >= e.last_seen_secs)
      ? (int32_t)((now_secs - e.last_seen_secs) / 60)
      : 0;
  int32_t fresh_term = 60 - age_minutes;
  if (fresh_term < 0) fresh_term = 0;
  if (fresh_term > 60) fresh_term = 60;

  // Hop penalty
  int32_t hop_term = -5 * (int32_t)e.hop_count;

  // Stability bonus
  int32_t stab_term = (int32_t)e.n_seen;
  if (stab_term > 10) stab_term = 10;

  return snr_term + fresh_term + hop_term + stab_term;
}

void RouteCache::prune(uint32_t now_secs) {
  // In-place compaction: keep only entries whose age <= _ttl_secs.
  int write = 0;
  for (int read = 0; read < _used; read++) {
    uint32_t age = (now_secs >= _entries[read].last_seen_secs)
        ? (now_secs - _entries[read].last_seen_secs)
        : 0;
    if (age <= _ttl_secs) {
      if (write != read) {
        _entries[write] = _entries[read];
      }
      write++;
    }
  }
  // Zero out the now-unused tail so getEntry() can't accidentally read stale data.
  if (write < _used) {
    memset(&_entries[write], 0, sizeof(RouteEntry) * (_used - write));
  }
  _used = write;
}

void RouteCache::clear() {
  _used = 0;
  memset(_entries, 0, sizeof(_entries));
}

bool RouteCache::getEntry(int idx, RouteEntry& out) const {
  if (idx < 0 || idx >= _used) return false;
  out = _entries[idx];
  return true;
}

int RouteCache::findExact(const uint8_t* dest_pubkey, const uint8_t* path, uint8_t hop_count) const {
  for (int i = 0; i < _used; i++) {
    const RouteEntry& e = _entries[i];
    if (memcmp(e.dest_pubkey, dest_pubkey, PUB_KEY_SIZE) != 0) continue;
    if (e.hop_count != hop_count) continue;
    if (hop_count > 0 && memcmp(e.path, path, hop_count) != 0) continue;
    return i;
  }
  return -1;
}

int RouteCache::findOldest() const {
  if (_used == 0) return -1;
  int oldest_idx = 0;
  uint32_t oldest_ts = _entries[0].last_seen_secs;
  for (int i = 1; i < _used; i++) {
    if (_entries[i].last_seen_secs < oldest_ts) {
      oldest_ts = _entries[i].last_seen_secs;
      oldest_idx = i;
    }
  }
  return oldest_idx;
}
