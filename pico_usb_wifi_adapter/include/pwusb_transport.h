#ifndef PWUSB_TRANSPORT_H
#define PWUSB_TRANSPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void pwusb_transport_init(void);
size_t pwusb_transport_rx_write(const uint8_t* data, size_t n);
bool pwusb_transport_try_get_msg(uint8_t* out, uint16_t* out_len);
void pwusb_transport_get_and_clear_stats(uint32_t* drop_bytes,
                                         uint32_t* drop_events,
                                         uint32_t* resync_bytes);

#endif
