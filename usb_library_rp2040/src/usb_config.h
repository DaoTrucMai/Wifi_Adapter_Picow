/**
 * Copyright (c) 2024 Daniel Gorbea
 *
 * Copyright (c) 2020 Raspberry Pi (Trading) Ltd. author of https://github.com/raspberrypi/pico-examples/tree/master/usb
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef USB_CONFIG_H
#define USB_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

#include "usb_common.h"

#define EP0_IN_ADDR (USB_DIR_IN | 0)
#define EP0_OUT_ADDR (USB_DIR_OUT | 0)
#define EP1_OUT_ADDR (USB_DIR_OUT | 1)
#define EP2_IN_ADDR (USB_DIR_IN | 2)

#define STAGE_SETUP 0
#define STAGE_DATA 1
#define STAGE_STATUS 2
#define STATUS_OK 0
#define STATUS_BUSY 1
#define STATUS_BUFFER_OVERFLOW 2
#define STATUS_LENGTH_OVERFLOW 3
#define PACKET_SIZE_CONTROL 64
#define PACKET_SIZE_INTERRUPT 64
#define PACKET_SIZE_BULK 64
#define PACKET_SIZE_ISO_128 128
#define PACKET_SIZE_ISO_256 256
#define PACKET_SIZE_ISO_512 512
#define UNKNOWN_SIZE -1

#define USB_VID 0xCAFE
#define USB_PID 0x4001
#define USB_BCD 0x0100

#define USB_CONFIG_TOTAL_LEN_BASE (sizeof(struct usb_configuration_descriptor) + sizeof(struct usb_interface_descriptor))
#define USB_IN_BUF_SIZE 32768
// EP1 OUT uses a buffered transfer so the callback runs per-chunk (not per
// 64-byte packet). This greatly reduces IRQ load and improves BULK OUT speed.
#define USB_OUT_BUF_SIZE 32768

typedef void (*usb_ep_handler)(uint8_t *buf, uint16_t len);
typedef void (*usb_control_transfer_handler)(uint8_t *buf, volatile struct usb_setup_packet *pkt, uint8_t stage);

void control_transfer_handler(uint8_t *buf, volatile struct usb_setup_packet *pkt, uint8_t stage);
void ep1_out_handler(uint8_t *buf, uint16_t len);
void ep2_in_handler(uint8_t *buf, uint16_t len);

static const struct usb_endpoint_descriptor ep0_out = {.bLength = sizeof(struct usb_endpoint_descriptor),
                                                       .bDescriptorType = USB_DT_ENDPOINT,
                                                       .bEndpointAddress = EP0_OUT_ADDR,
                                                       .bmAttributes = USB_TRANSFER_TYPE_CONTROL,
                                                       .wMaxPacketSize = PACKET_SIZE_CONTROL,
                                                       .bInterval = 0};

static const struct usb_endpoint_descriptor ep0_in = {.bLength = sizeof(struct usb_endpoint_descriptor),
                                                      .bDescriptorType = USB_DT_ENDPOINT,
                                                      .bEndpointAddress = EP0_IN_ADDR,
                                                      .bmAttributes = USB_TRANSFER_TYPE_CONTROL,
                                                      .wMaxPacketSize = PACKET_SIZE_CONTROL,
                                                      .bInterval = 0};

static const struct usb_endpoint_descriptor ep1_out = {.bLength = sizeof(struct usb_endpoint_descriptor),
                                                       .bDescriptorType = USB_DT_ENDPOINT,
                                                       .bEndpointAddress = EP1_OUT_ADDR,
                                                       .bmAttributes = USB_TRANSFER_TYPE_BULK,
                                                       .wMaxPacketSize = PACKET_SIZE_BULK,
                                                       .bInterval = 1};

static const struct usb_endpoint_descriptor ep2_in = {.bLength = sizeof(struct usb_endpoint_descriptor),
                                                      .bDescriptorType = USB_DT_ENDPOINT,
                                                      .bEndpointAddress = EP2_IN_ADDR,
                                                      .bmAttributes = USB_TRANSFER_TYPE_BULK,
                                                      .wMaxPacketSize = PACKET_SIZE_BULK,
                                                      .bInterval = 1};

struct usb_endpoint_configuration {
    const struct usb_endpoint_descriptor *descriptor;
    usb_ep_handler handler;
    volatile uint32_t *endpoint_control;
    volatile uint32_t *buffer_control;
    volatile uint8_t *dpram_buffer_a;
    volatile uint8_t *dpram_buffer_b;
    uint8_t *data_buffer;
    bool double_buffer;
    uint8_t next_pid;
    int32_t length;
    int32_t pos;
    int32_t pos_send;
    bool is_start;
    bool is_completed;
    uint status;
    uint data_buffer_size;
    uint bit;
};

struct usb_device_configuration {
    const struct usb_device_descriptor *device_descriptor;
    const struct usb_interface_descriptor *interface_descriptor;
    const struct usb_configuration_descriptor *config_descriptor;
    const unsigned char *lang_descriptor;
    const unsigned char **descriptor_strings;
    struct usb_endpoint_configuration endpoints[USB_NUM_ENDPOINTS];
    usb_control_transfer_handler control_transfer_handler;
};

extern uint8_t g_usb_in_buf[USB_IN_BUF_SIZE];
extern uint8_t g_usb_out_buf[USB_OUT_BUF_SIZE];

static const struct usb_device_descriptor device_descriptor = {
    .bLength = sizeof(struct usb_device_descriptor),
    .bDescriptorType = USB_DT_DEVICE,
    .bcdUSB = 0x0200,        // USB 2.0 device (Full-Speed)
    .bDeviceClass = 0,       // Specified in interface descriptor
    .bDeviceSubClass = 0,    // No subclass
    .bDeviceProtocol = 0,    // No protocol
    .bMaxPacketSize0 = 64,   // Max packet size for ep0
    .idVendor = USB_VID,
    .idProduct = USB_PID,
    .bcdDevice = USB_BCD,
    .iManufacturer = 1,      // Manufacturer string index
    .iProduct = 2,           // Product string index
    .iSerialNumber = 3,      // Serial string index
    .bNumConfigurations = 1  // One configuration
};

static struct usb_interface_descriptor interface_descriptor = {
    .bLength = sizeof(struct usb_interface_descriptor),
    .bDescriptorType = USB_DT_INTERFACE,
    .bInterfaceNumber = 0,
    .bAlternateSetting = 0,
    .bInterfaceClass = 0xff,  // Vendor specific endpoint
    .bInterfaceSubClass = 0,
    .bInterfaceProtocol = 0,
    .iInterface = 0};

static struct usb_configuration_descriptor config_descriptor = {
    .bLength = sizeof(struct usb_configuration_descriptor),
    .bDescriptorType = USB_DT_CONFIG,
    .wTotalLength = USB_CONFIG_TOTAL_LEN_BASE,
    .bNumInterfaces = 1,
    .bConfigurationValue = 1,  // Configuration 1
    .iConfiguration = 0,       // No string
    .bmAttributes = 0x80,      // attributes: bus powered, no remote wakeup
    .bMaxPower = 0x32          // 100ma
};

static const unsigned char lang_descriptor[] = {
    4,          // bLength
    0x03,       // bDescriptorType == String Descriptor
    0x09, 0x04  // language id = us english
};

static const unsigned char *descriptor_strings[] = {
    (unsigned char *)"MyUniversity",           // Manufacturer
    (unsigned char *)"PicoW USB WiFi Adapter", // Product
    (unsigned char *)"0001"                    // Serial
};

#ifdef __cplusplus
}
#endif

#endif
