#ifndef WIFI_MGR_H
#define WIFI_MGR_H

#include <stdbool.h>
#include <stdint.h>

#include "msg_queue.h"

bool wifi_mgr_init(void);
void wifi_mgr_set_txq(msg_queue_t* txq);
void wifi_mgr_poll(void);

// Start a scan; results will be enqueued as USB events
bool wifi_mgr_scan_start(msg_queue_t* txq, uint16_t seq);
bool wifi_mgr_connect(msg_queue_t* txq, uint16_t seq,
                      const char* ssid, uint8_t ssid_len,
                      const char* psk, uint8_t psk_len);
bool wifi_mgr_disconnect(msg_queue_t* txq, uint16_t seq);
void wifi_mgr_get_status(msg_queue_t* txq, uint16_t seq);
bool wifi_mgr_send_ethernet(const uint8_t* buf, uint16_t len);

#endif
