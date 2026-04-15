/**
 * Copyright (c) 2024 Daniel Gorbea
 * 
 * Copyright (c) 2020 Raspberry Pi (Trading) Ltd. author of https://github.com/raspberrypi/pico-examples/tree/master/usb
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "usb_config.h"

static uint8_t ep0_buf[4096];
uint8_t g_usb_in_buf[USB_IN_BUF_SIZE];
uint8_t g_usb_out_buf[USB_OUT_BUF_SIZE];

static struct usb_device_configuration dev_config = {.device_descriptor = &device_descriptor,
                                                     .interface_descriptor = &interface_descriptor,
                                                     .config_descriptor = &config_descriptor,
                                                     .lang_descriptor = lang_descriptor,
                                                     .descriptor_strings = descriptor_strings,
                                                     .control_transfer_handler = &control_transfer_handler,
                                                     .endpoints = {{
                                                                       .descriptor = &ep0_out,
                                                                       .double_buffer = false, // Double buffer not supported for EP0
                                                                       .data_buffer = ep0_buf,
                                                                       .data_buffer_size = sizeof(ep0_buf),
                                                                   },
                                                                   {
                                                                       .descriptor = &ep0_in,
                                                                       .double_buffer = false, // Double buffer not supported for EP0
                                                                       .data_buffer = ep0_buf,
                                                                       .data_buffer_size = sizeof(ep0_buf),
                                                                   },
                                                                   {
                                                                       .descriptor = &ep1_out,
                                                                       .handler = &ep1_out_handler,
                                                                       .double_buffer = true,
                                                                       /*
                                                                        * Stream OUT packets to the handler (64B max-packet
                                                                        * chunks). Bulk OUT is a byte stream; relying on "short
                                                                        * packet" boundaries to delimit application messages is
                                                                        * not reliable (messages can be a multiple of 64).
                                                                        */
                                                                       .data_buffer = NULL,
                                                                       .data_buffer_size = 0,
                                                                   },
                                                                   {
                                                                       .descriptor = &ep2_in,
                                                                       .handler = &ep2_in_handler,
                                                                       // Keep EP2 IN single-buffered for correctness. The
                                                                       // current RP2040 backend's double-buffered buffered-IN
                                                                       // path is not reliable enough for protocol traffic like
                                                                       // HELLO_RSP and can stall device->host transfers
                                                                       // completely.
                                                                       .double_buffer = false,
                                                                       .data_buffer = g_usb_in_buf,
                                                                       .data_buffer_size = sizeof(g_usb_in_buf),
                                                                   }}};
