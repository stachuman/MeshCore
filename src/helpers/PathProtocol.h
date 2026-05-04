#pragma once

// === Universal inter-router/companion RPC envelope ===
//
// PAYLOAD_TYPE_CONTROL (0x0B), zero-hop, subtype CTL_TYPE_NEIGHBOR_RPC = 0xC0.
//
// This subtype is the generic 1-hop RPC framework between MeshCore nodes
// (router-to-router, router-to-companion, companion-to-companion). 
// future neighbor protocols — route gossip, congestion announcements, neighbor
// stats, time-slot negotiation... — MUST add new `rpc_op` sub-command values
// rather than allocate fresh CTL_TYPE_* subtypes. Treat the rpc_op space as the
// stable, evolution-friendly extension point.
//
// === Subtype byte layout ===
//
//   bits 7..4 : 0xC = CTL_TYPE_NEIGHBOR_RPC (high nibble fixed; high bit 0x80
//               set so MeshCore's existing zero-hop CONTROL gate at Mesh.cpp
//               picks it up).
//   bits 3..2 : hash_size_minus_1 — 0 = 1-byte hashes, 1 = 2 bytes, 2 = 3 bytes.
//               Sets the on-wire size of sender_hash AND of the path bytes
//               carried inside the rpc_op payload. Matches MeshCore's
//               NodePrefs.path_hash_mode + 1 convention. The querier picks the
//               size when sending PATH_REQ; the responder MUST echo the same
//               size on its OFFER.
//   bits 1..0 : rpc-op-specific flags (e.g., PATH_REQ_FLAG_FULL_TARGET = 0x01).
//
// Wire format (PAYLOAD_TYPE_CONTROL payload, sent via Mesh::sendZeroHop)
//
//   byte 0     subtype           see above
//   byte 1..H  sender_hash       H bytes (H = ((subtype >> 2) & 0x03) + 1)
//   byte 1+H   recipient_hash    1 byte (NEIGHBOR_RPC_BROADCAST_HASH = 0x00 for
//                                unaddressed broadcasts; 1 byte is enough for
//                                "is this for me?" — combined with query_id for
//                                disambiguation)
//   byte 2+H   query_id          1 byte random correlation tag (0 reserved)
//   byte 3+H   rpc_op            1 byte sub-command — see RPC_OP_* below
//   byte 4+H   payload_len       1 byte (length of bytes 5+H..end; lets a node
//                                that doesn't recognize the rpc_op skip the body)
//   byte 5+H+  payload           rpc_op-specific layout
//
// Forward-compat guarantee: a node that doesn't recognize an rpc_op can still
// parse the envelope (size derivable from subtype) and skip the body cleanly.
//
// rpc_op space conventions:
//   0x01..0x7F   feature ops (path-discovery, routing commands)
//   0x80..0xFF   reserved for protocol version bumps if framing ever needs to evolve

#include <stdint.h>

#define CTL_TYPE_NEIGHBOR_RPC               0xC0
#define NEIGHBOR_RPC_BROADCAST_HASH         0x00   // sentinel for "unaddressed" recipient_hash
#define NEIGHBOR_RPC_MAX_HASH_SIZE          3      // max bytes per sender_hash / per path-byte hash

// Subtype encoding helpers
#define NEIGHBOR_RPC_SUBTYPE_HIGH_NIBBLE    0xF0   // mask for the type-class nibble
#define NEIGHBOR_RPC_HASH_SIZE_MASK         0x0C   // bits 3..2: hash_size_minus_1
#define NEIGHBOR_RPC_HASH_SIZE_SHIFT        2
#define NEIGHBOR_RPC_FLAGS_MASK             0x03   // bits 1..0: op flags

// Decode hash_size (1, 2, or 3) from a subtype byte.
static inline uint8_t neighbor_rpc_hash_size(uint8_t subtype) {
  return (uint8_t)(((subtype & NEIGHBOR_RPC_HASH_SIZE_MASK) >> NEIGHBOR_RPC_HASH_SIZE_SHIFT) + 1);
}

// Build a subtype byte. hash_size must be 1, 2, or 3; op_flags is the rpc_op-specific 2-bit flags.
static inline uint8_t neighbor_rpc_subtype(uint8_t hash_size, uint8_t op_flags) {
  uint8_t hs = (hash_size > 0) ? (uint8_t)(hash_size - 1) : 0;
  if (hs > 2) hs = 2;
  return (uint8_t)(CTL_TYPE_NEIGHBOR_RPC
                   | ((hs << NEIGHBOR_RPC_HASH_SIZE_SHIFT) & NEIGHBOR_RPC_HASH_SIZE_MASK)
                   | (op_flags & NEIGHBOR_RPC_FLAGS_MASK));
}

// Header sizes — base = subtype + recipient_hash + query_id + rpc_op + payload_len = 5 bytes.
// Variable part (sender_hash) adds 1, 2, or 3 bytes depending on hash_size.
#define NEIGHBOR_RPC_HEADER_BASE_SIZE       5
#define NEIGHBOR_RPC_HEADER_MIN_SIZE        (NEIGHBOR_RPC_HEADER_BASE_SIZE + 1)  // 1-byte hash
#define NEIGHBOR_RPC_HEADER_MAX_SIZE        (NEIGHBOR_RPC_HEADER_BASE_SIZE + NEIGHBOR_RPC_MAX_HASH_SIZE)  // = 8

// Compute total header size for a given hash_size.
static inline uint8_t neighbor_rpc_header_size(uint8_t hash_size) {
  return (uint8_t)(NEIGHBOR_RPC_HEADER_BASE_SIZE + hash_size);
}

// === rpc_op sub-command catalog ===
#define RPC_OP_PATH_REQ     0x01    // querier asks 1-hop neighborhood for a route to target
#define RPC_OP_PATH_OFFER   0x02    // responder answers with cached route from RouteCache
// 0x03..0x7F reserved for future neighbor commands - 1-hop

// === RPC_OP_PATH_REQ flags (low 2 bits of subtype) ===
#define PATH_REQ_FLAG_FULL_TARGET           0x01   // payload includes 32-byte full pubkey for hash-collision disambig

// === RPC_OP_PATH_REQ payload (follows the variable-size common header) ===
//
//   byte 0..3 target_hash       4 bytes — first 4 bytes of destination pubkey.
//                               Fixed 4-byte width independent of hash_size:
//                               cache lookup precision (avoid prefix collisions)
//                               is decoupled from path-routing hash size.
//   byte 4..  full_target       OPTIONAL PUB_KEY_SIZE (32) bytes IF (subtype low nibble & PATH_REQ_FLAG_FULL_TARGET)
//   next      exclude_len       1 byte — count of hashes in exclude_path (0..PATH_REQ_EXCLUDE_HASHES_MAX)
//   next..    exclude_path      exclude_len * hash_size bytes — path the querier just tried
#define PATH_REQ_TARGET_HASH_SIZE           4
#define PATH_REQ_FULL_TARGET_SIZE           32   // PUB_KEY_SIZE
#define PATH_REQ_PAYLOAD_MIN                (PATH_REQ_TARGET_HASH_SIZE + 1)  // target + exclude_len
#define PATH_REQ_EXCLUDE_BYTES_MAX          16   // matches ROUTE_CACHE_PATH_MAX (raw byte buffer)
#define PATH_REQ_PAYLOAD_MAX                (PATH_REQ_TARGET_HASH_SIZE + PATH_REQ_FULL_TARGET_SIZE \
                                             + 1 + PATH_REQ_EXCLUDE_BYTES_MAX)
                                                  // = 4 + 32 + 1 + 16 = 53 bytes
#define PATH_REQ_MAX_BYTES                  (NEIGHBOR_RPC_HEADER_MAX_SIZE + PATH_REQ_PAYLOAD_MAX)
                                                  // = 8 + 53 = 61 bytes total packet

// === RPC_OP_PATH_OFFER payload (follows the variable-size common header) ===
//
//   byte 0..3 target_hash       4 bytes — echoed from request
//   byte 4    hop_count         path length in hashes (0..PATH_OFFER_PATH_HASHES_MAX_AT_HASH_SIZE)
//   byte 5    last_snr_x4       int8_t — responder's last observed SNR×4 (saturated)
//   byte 6..7 age_secs          uint16 — seconds since last observation, capped at 65535
//   byte 8..  path              hop_count * hash_size bytes — forwarder hashes from responder
//                               to target. Querier prepends sender_hash (from common header)
//                               at the same hash_size to build the full source-route path.
#define PATH_OFFER_PAYLOAD_MIN              (PATH_REQ_TARGET_HASH_SIZE + 1 + 1 + 2)  // 4 + 1 + 1 + 2 = 8
#define PATH_OFFER_PATH_BYTES_MAX           16   // matches ROUTE_CACHE_PATH_MAX (raw byte buffer)
#define PATH_OFFER_PAYLOAD_MAX              (PATH_OFFER_PAYLOAD_MIN + PATH_OFFER_PATH_BYTES_MAX)
                                                  // = 8 + 16 = 24 bytes
#define PATH_OFFER_MAX_BYTES                (NEIGHBOR_RPC_HEADER_MAX_SIZE + PATH_OFFER_PAYLOAD_MAX)
                                                  // = 8 + 24 = 32 bytes total packet

// The repeater's PATH_OFFER builder uses a fixed-size data[PATH_OFFER_MAX_BYTES] buffer.
// If anyone adds a field to PATH_OFFER (or grows path-bytes max) without bumping these
// constants in lockstep, the buffer overflows silently. Keep the arithmetic explicit.
#ifdef __cplusplus
static_assert(PATH_OFFER_MAX_BYTES
              == NEIGHBOR_RPC_HEADER_MAX_SIZE
                 + PATH_REQ_TARGET_HASH_SIZE + 1 /*hops*/ + 1 /*snr*/ + 2 /*age*/
                 + PATH_OFFER_PATH_BYTES_MAX,
              "PATH_OFFER_MAX_BYTES arithmetic out of sync with field layout");
#endif
