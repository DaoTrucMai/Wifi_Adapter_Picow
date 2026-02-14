#ifndef PICO_WIFI_CFG80211_H
#define PICO_WIFI_CFG80211_H

#include <linux/types.h>

struct pico_dev;
struct pico_cfg80211;
struct net_device;
struct device;

enum pico_key_type {
    PICO_KEY_NONE = 0,
    PICO_KEY_PASSPHRASE = 1,
    PICO_KEY_PMK = 2,
};

struct pico_cfg80211* pico_cfg80211_init(struct pico_dev* pdev,
                                         struct net_device* ndev,
                                         struct device* dev);
void pico_cfg80211_deinit(struct pico_cfg80211* cfg);

void pico_cfg80211_report_scan_result(struct pico_cfg80211* cfg,
                                      const u8* bssid,
                                      u8 channel,
                                      s8 rssi,
                                      u16 security,
                                      const char* ssid,
                                      u8 ssid_len);
void pico_cfg80211_scan_done(struct pico_cfg80211* cfg, bool aborted);
void pico_cfg80211_conn_state(struct pico_cfg80211* cfg,
                              bool connected,
                              const u8* bssid,
                              const char* ssid,
                              u8 ssid_len,
                              u16 status,
                              s8 rssi,
                              u8 channel);

int pico_ctrl_scan_start(struct pico_dev* pdev);
int pico_ctrl_connect(struct pico_dev* pdev,
                      const u8* ssid, u8 ssid_len,
                      const u8* psk, u8 psk_len,
                      u8 key_type);
int pico_ctrl_disconnect(struct pico_dev* pdev);

#endif
