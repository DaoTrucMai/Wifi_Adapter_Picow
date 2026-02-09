#ifndef PWUSB_HANDLERS_H
#define PWUSB_HANDLERS_H

#include <stdbool.h>
#include <stdint.h>

#include "msg_queue.h"

bool pwusb_handle_one(msg_queue_t* txq, const uint8_t* msg, uint16_t msg_len);

#endif
