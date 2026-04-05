#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "msg_queue.h"

#ifdef __cplusplus
extern "C" {
#endif

// Handle one fully reassembled PWUSB message from host.
void pwusb_handle_one(msg_queue_t* txq, const uint8_t* msg, uint16_t len);

// Benchmark source generator (device -> host).
// Call this periodically from main loop.
void pwusb_bench_poll(msg_queue_t* txq);

// Returns true if any raw USB benchmark mode is active.
bool pwusb_bench_is_active(void);

#ifdef __cplusplus
}
#endif