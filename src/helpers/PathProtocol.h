#pragma once

// === Universal inter-router/companion RPC envelope ===
//
// PAYLOAD_TYPE_CONTROL (0x0B), zero-hop, subtype CTL_TYPE_NEIGHBOR_RPC = 0xC0.
//
// This subtype is the generic 1-hop RPC framework between MeshCore nodes
// (router-to-router, router-to-companion, companion-to-companion). Phase 2
// of the routing work introduces it for path-discovery (PATH_REQ / PATH_OFFER);
// future neighbor protocols — route gossip, congestion announcements, neighbor
// stats, time-slot negotiation, etc. — MUST add new `rpc_op` sub-command values
// rather than allocate fresh CTL_TYPE_* subtypes. Treat the rpc_op space as the
// stable, evolution-friendly extension point.
//
// Forward-compatibility guarantee: every packet shares a 6-byte common header
// ending in payload_len, so a node that doesn't recognize an rpc_op can still
// parse the envelope, skip the body cleanly, and never misinterpret bytes as
// a different op.
//
// Wire format (PAYLOAD_TYPE_CONTROL payload, sent via Mesh::sendZeroHop):
//
//   byte 0  subtype           high nibble = 0xC0 (CTL_TYPE_NEIGHBOR_RPC)
//                             low nibble  = rpc-op-specific flags
//                             (high bit 0x80 set; required by Mesh.cpp:67's
//                             zero-hop CONTROL dispatch gate)
//   byte 1  sender_hash       PATH_HASH_SIZE prefix of sender's pubkey
//   byte 2  recipient_hash    PATH_HASH_SIZE prefix of intended addressee
//                             (NEIGHBOR_RPC_BROADCAST_HASH = 0x00 for unaddressed
//                             requests; receiver decides per rpc_op semantics
//                             whether to act on broadcasts)
//   byte 3  query_id          random 1-byte correlation tag (0 reserved as sentinel)
//   byte 4  rpc_op            sub-command — see RPC_OP_* below
//   byte 5  payload_len       length of bytes 6..end (0..MAX_PACKET_PAYLOAD-6)
//   byte 6+ payload           rpc_op-specific layout
//
// rpc_op space conventions:
//   0x01..0x7F   feature ops (path-discovery, route gossip, neighbor stats, ...)
//   0x80..0xFF   reserved for protocol version bumps if framing ever needs to evolve

#include <stdint.h>

#define CTL_TYPE_NEIGHBOR_RPC      0xC0
#define NEIGHBOR_RPC_HEADER_SIZE   6
#define NEIGHBOR_RPC_BROADCAST_HASH  0x00   // sentinel for "unaddressed" recipient_hash

// === rpc_op sub-command catalog ===
#define RPC_OP_PATH_REQ     0x01    // querier asks 1-hop neighborhood for a route to target
#define RPC_OP_PATH_OFFER   0x02    // responder answers with cached route from RouteCache
// 0x03..0x7F reserved for future neighbor RPCs

// === Subtype low-nibble flags (rpc_op-specific) ===
//
// For RPC_OP_PATH_REQ:
#define PATH_REQ_FLAG_FULL_TARGET   0x01   // payload includes 32-byte full pubkey for hash-collision disambig

// === RPC_OP_PATH_REQ payload (follows the 6-byte common header) ===
//
//   byte 0    target_hash       PATH_HASH_SIZE prefix of destination pubkey
//   byte 1..  full_target       OPTIONAL PUB_KEY_SIZE bytes IF (subtype low nibble & PATH_REQ_FLAG_FULL_TARGET)
//   next      exclude_len       1 byte (0..PATH_REQ_EXCLUDE_MAX)
//   next..    exclude_path      exclude_len bytes — the path the querier just tried
#define PATH_REQ_FULL_TARGET_SIZE   32   // optional; gated by flag bit 0
#define PATH_REQ_EXCLUDE_MAX        16   // matches ROUTE_CACHE_PATH_MAX
#define PATH_REQ_PAYLOAD_MIN        2    // target_hash + exclude_len when no full_target / no exclude
#define PATH_REQ_PAYLOAD_MAX        (1 + PATH_REQ_FULL_TARGET_SIZE + 1 + PATH_REQ_EXCLUDE_MAX)
                                          // = 50 bytes payload
#define PATH_REQ_MAX_BYTES          (NEIGHBOR_RPC_HEADER_SIZE + PATH_REQ_PAYLOAD_MAX)
                                          // = 56 bytes total packet

// === RPC_OP_PATH_OFFER payload (follows the 6-byte common header) ===
//
//   byte 0    target_hash       echoes the request's target_hash
//   byte 1    hop_count         path length in 1-byte hashes (0..PATH_OFFER_PATH_MAX)
//   byte 2    last_snr_x4       int8_t — responder's last observed SNR×4 to target
//   byte 3..4 age_secs          uint16 — seconds since last observation (capped at 65535)
//   byte 5..  path              hop_count bytes — forwarder hashes from responder to target;
//                               querier prepends sender_hash (from common header) to build full path
#define PATH_OFFER_PAYLOAD_MIN      5    // target_hash + hop_count + snr + age (2 bytes)
#define PATH_OFFER_PATH_MAX         16   // matches ROUTE_CACHE_PATH_MAX
#define PATH_OFFER_PAYLOAD_MAX      (PATH_OFFER_PAYLOAD_MIN + PATH_OFFER_PATH_MAX)
                                          // = 21 bytes payload
#define PATH_OFFER_MAX_BYTES        (NEIGHBOR_RPC_HEADER_SIZE + PATH_OFFER_PAYLOAD_MAX)
                                          // = 27 bytes total packet
