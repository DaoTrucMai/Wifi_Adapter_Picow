#ifndef USB_BACKEND_H
#define USB_BACKEND_H

#include <stdbool.h>
#include <stdint.h>

/*
 * USB backend abstraction.
 *
 * The framed PHTM protocol stays identical regardless of whether firmware uses
 * TinyUSB or usb_library_rp2040 underneath. Only the backend implementation
 * should change.
 */

void usb_backend_init(void);
void usb_backend_poll_rx(void);
void usb_backend_try_tx(void);

void usb_backend_bench_set_src(bool enable, uint16_t payload_len);
void usb_backend_bench_set_sink(bool enable);

#endif

