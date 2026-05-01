#pragma once

// PATH_REQ / PATH_OFFER zero-hop subtypes within PAYLOAD_TYPE_CONTROL.
// See docs/superpowers/specs/2026-04-29-meshcore-routing-design.md §6.
//
// Wire format dispatch: payload[0] & 0xF0 == subtype; high bit (0x80) is the
// zero-hop gate (Mesh.cpp:67-73). Low nibble is flags.

#include <stdint.h>

#define CTL_TYPE_PATH_REQ      0xA0   // endpoint asks 1-hop neighborhood for a route
#define CTL_TYPE_PATH_OFFER    0xB0   // repeater answers from its RouteCache

// PATH_REQ low-nibble flags
#define PATH_REQ_FLAG_FULL_TARGET   0x01   // full pubkey follows (32 bytes) for hash-collision disambig

// PATH_REQ wire layout (1-byte path hashes; PATH_HASH_SIZE=1 assumed):
//
//   offset 0  subtype          1 byte (0xA0 | flags)
//   offset 1  querier_hash     1 byte (PATH_HASH_SIZE prefix of querier pubkey)
//   offset 2  query_id         1 byte (random; lets querier match offers)
//   offset 3  target_hash      1 byte (PATH_HASH_SIZE prefix of destination pubkey)
//   offset 4  full_target?     32 bytes IF (subtype & PATH_REQ_FLAG_FULL_TARGET)
//   offset N  exclude_len      1 byte (0..16; length of exclude_path; 0 = no exclusion)
//   offset N+1 exclude_path    exclude_len bytes (the path the querier just tried)
#define PATH_REQ_HEADER_SIZE        4   // bytes 0..3 always present
#define PATH_REQ_FULL_TARGET_SIZE   32  // optional, gated by flag bit 0
#define PATH_REQ_EXCLUDE_MAX        16  // matches ROUTE_CACHE_PATH_MAX
#define PATH_REQ_MAX_BYTES          (PATH_REQ_HEADER_SIZE + PATH_REQ_FULL_TARGET_SIZE + 1 + PATH_REQ_EXCLUDE_MAX)
                                    // = 53 bytes max

// PATH_OFFER wire layout (1-byte path hashes assumed):
//
//   offset 0  subtype          1 byte (0xB0)
//   offset 1  querier_hash     1 byte (echoes request)
//   offset 2  query_id         1 byte (echoes request)
//   offset 3  target_hash      1 byte (echoes request)
//   offset 4  responder_hash   1 byte (PATH_HASH_SIZE prefix of responder's pubkey;
//                                     querier prepends this to build full path)
//   offset 5  hop_count        1 byte (0..16; length of path[])
//   offset 6  last_snr_x4      1 byte (int8_t; responder's last observed SNR×4)
//   offset 7  age_secs         2 bytes (uint16; seconds since last observation, capped)
//   offset 9  path             hop_count bytes (forwarder hashes from responder to target)
//
// NOTE: this differs from spec §6.3 by inserting `responder_hash` at offset 4.
// The spec was missing it; without it the querier can't build a complete path.
#define PATH_OFFER_HEADER_SIZE     9    // bytes 0..8 always present
#define PATH_OFFER_PATH_MAX        16   // matches ROUTE_CACHE_PATH_MAX
#define PATH_OFFER_MAX_BYTES       (PATH_OFFER_HEADER_SIZE + PATH_OFFER_PATH_MAX)
                                   // = 25 bytes max
