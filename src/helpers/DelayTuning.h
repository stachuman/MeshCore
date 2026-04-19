#pragma once

#include <stdint.h>

struct DelayTuning {
  float tx_delay;
  float direct_tx_delay;
};

// Empirically tuned via Seattle-area topology sweep (delay_optimization_v2, 2026-04).
// Values follow: tx(n) = 2.4 + 0.2 * n^1.9, dtx(n) = 1.1 + 0.6 * n^1.9
// rx_delay_base intentionally NOT set by auto-tune: score-based RX queueing
// has no measurable effect on delivery rate in realistic topologies.
static const DelayTuning DELAY_TUNING_TABLE[] = {
  {  2.4f,    1.1f},  //  0 neighbors (isolated)
  {  2.6f,    1.7f},  //  1
  {  3.1f,    3.3f},  //  2
  {  4.0f,    5.9f},  //  3
  {  5.2f,    9.5f},  //  4
  {  6.7f,   13.9f},  //  5 (medium)
  {  8.4f,   19.2f},  //  6
  { 10.5f,   25.3f},  //  7
  { 12.8f,   32.3f},  //  8
  { 15.4f,   40.1f},  //  9 (dense)
  { 18.3f,   48.8f},  // 10
  { 21.4f,   58.2f},  // 11
  { 24.9f,   68.5f},  // 12
  { 28.6f,   79.6f},  // 13
  { 32.5f,   91.4f},  // 14
  { 36.7f,  104.1f},  // 15
  { 41.2f,  117.5f},  // 16
  { 45.9f,  131.7f},  // 17
  { 50.9f,  146.7f},  // 18
  { 56.2f,  162.5f},  // 19
  { 61.7f,  179.0f},  // 20
  { 67.4f,  196.2f},  // 21
  { 73.5f,  214.3f},  // 22
  { 79.7f,  233.1f},  // 23
  { 86.2f,  252.6f},  // 24+ (very dense)
};
#define DELAY_TUNING_TABLE_SIZE  25

static inline const DelayTuning& getDelayTuning(int neighbor_count) {
  int idx = neighbor_count;
  if (idx < 0) idx = 0;
  if (idx >= DELAY_TUNING_TABLE_SIZE) idx = DELAY_TUNING_TABLE_SIZE - 1;
  return DELAY_TUNING_TABLE[idx];
}
