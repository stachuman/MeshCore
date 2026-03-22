#pragma once

#include <stdint.h>

struct DelayTuning {
  float tx_delay;
  float direct_tx_delay;
  float rx_delay_base;
};

// White Paper 1, Section 8.0 — indexed by active neighbor count (SNR > 0, heard within defined no days - default - 7days)
static const DelayTuning DELAY_TUNING_TABLE[] = {
  {1.0f, 0.4f, 2.0f},  // 0 neighbors (sparse)
  {1.1f, 0.5f, 2.0f},  // 1
  {1.2f, 0.6f, 3.0f},  // 2
  {1.2f, 0.6f, 3.0f},  // 3
  {1.3f, 0.7f, 3.0f},  // 4 (medium)
  {1.4f, 0.7f, 3.0f},  // 5
  {1.5f, 0.7f, 4.0f},  // 6
  {1.6f, 0.8f, 4.0f},  // 7
  {1.7f, 0.8f, 4.0f},  // 8
  {1.8f, 0.8f, 5.0f},  // 9 (dense)
  {1.9f, 0.9f, 6.0f},  // 10
  {2.0f, 0.9f, 7.0f},  // 11 (regional)
  {2.0f, 0.9f, 8.0f},  // 12+
};
#define DELAY_TUNING_TABLE_SIZE  13

static inline const DelayTuning& getDelayTuning(int neighbor_count) {
  int idx = neighbor_count;
  if (idx < 0) idx = 0;
  if (idx >= DELAY_TUNING_TABLE_SIZE) idx = DELAY_TUNING_TABLE_SIZE - 1;
  return DELAY_TUNING_TABLE[idx];
}
