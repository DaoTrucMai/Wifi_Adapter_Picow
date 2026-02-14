#include "pico_wifi_cfg80211.h"

#include <linux/etherdevice.h>
#include <linux/ieee80211.h>
#include <linux/version.h>
#include <net/cfg80211.h>

struct pico_cfg80211 {
    struct wiphy* wiphy;
    struct wireless_dev* wdev;
    struct pico_dev* pdev;

    spinlock_t lock;
    struct cfg80211_scan_request* scan_req;
    bool scan_aborted;

    struct work_struct scan_done_work;
    struct work_struct conn_work;

    bool connect_in_progress;
    bool disconnect_requested;
    bool is_connected;
    bool prev_connected;

    u8 bssid[ETH_ALEN];
    char ssid[32];
    u8 ssid_len;
    u16 status;
    s8 rssi;
    u8 channel;
};

static struct ieee80211_channel pico_2ghz_channels[] = {
    {.center_freq = 2412, .hw_value = 1, .max_power = 20},
    {.center_freq = 2417, .hw_value = 2, .max_power = 20},
    {.center_freq = 2422, .hw_value = 3, .max_power = 20},
    {.center_freq = 2427, .hw_value = 4, .max_power = 20},
    {.center_freq = 2432, .hw_value = 5, .max_power = 20},
    {.center_freq = 2437, .hw_value = 6, .max_power = 20},
    {.center_freq = 2442, .hw_value = 7, .max_power = 20},
    {.center_freq = 2447, .hw_value = 8, .max_power = 20},
    {.center_freq = 2452, .hw_value = 9, .max_power = 20},
    {.center_freq = 2457, .hw_value = 10, .max_power = 20},
    {.center_freq = 2462, .hw_value = 11, .max_power = 20},
    {.center_freq = 2467, .hw_value = 12, .max_power = 20},
    {.center_freq = 2472, .hw_value = 13, .max_power = 20},
};

static struct ieee80211_rate pico_2ghz_rates[] = {
    {.bitrate = 10, .hw_value = 0x1, .flags = IEEE80211_RATE_SHORT_PREAMBLE},   // 1 Mbps
    {.bitrate = 20, .hw_value = 0x2, .flags = IEEE80211_RATE_SHORT_PREAMBLE},   // 2 Mbps
    {.bitrate = 55, .hw_value = 0x4, .flags = IEEE80211_RATE_SHORT_PREAMBLE},   // 5.5 Mbps
    {.bitrate = 110, .hw_value = 0x8, .flags = IEEE80211_RATE_SHORT_PREAMBLE},  // 11 Mbps
    {.bitrate = 60, .hw_value = 0x10},                                          // 6 Mbps
    {.bitrate = 90, .hw_value = 0x20},                                          // 9 Mbps
    {.bitrate = 120, .hw_value = 0x40},                                         // 12 Mbps
    {.bitrate = 180, .hw_value = 0x80},                                         // 18 Mbps
    {.bitrate = 240, .hw_value = 0x100},                                        // 24 Mbps
    {.bitrate = 360, .hw_value = 0x200},                                        // 36 Mbps
    {.bitrate = 480, .hw_value = 0x400},                                        // 48 Mbps
    {.bitrate = 540, .hw_value = 0x800},                                        // 54 Mbps
};

static struct ieee80211_supported_band pico_band_2ghz = {
    .channels = pico_2ghz_channels,
    .n_channels = ARRAY_SIZE(pico_2ghz_channels),
    .bitrates = pico_2ghz_rates,
    .n_bitrates = ARRAY_SIZE(pico_2ghz_rates),
};

static void pico_cfg80211_scan_done_work(struct work_struct* work) {
    struct pico_cfg80211* cfg = container_of(work, struct pico_cfg80211, scan_done_work);
    struct cfg80211_scan_request* req;
    bool aborted;

    if (!cfg || !cfg->wiphy)
        return;

    spin_lock_bh(&cfg->lock);
    req = cfg->scan_req;
    cfg->scan_req = NULL;
    aborted = cfg->scan_aborted;
    cfg->scan_aborted = false;
    spin_unlock_bh(&cfg->lock);

    if (!req)
        return;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
    {
        struct cfg80211_scan_info info = {
            .aborted = aborted,
        };
        cfg80211_scan_done(req, &info);
    }
#else
    cfg80211_scan_done(req, aborted);
#endif
}

static bool pico_cfg80211_has_psk_akm(const struct cfg80211_crypto_settings* crypto) {
    int i;

    if (!crypto)
        return false;

    for (i = 0; i < crypto->n_akm_suites; i++) {
        switch (crypto->akm_suites[i]) {
            case WLAN_AKM_SUITE_PSK:
            case WLAN_AKM_SUITE_PSK_SHA256:
                return true;
            default:
                break;
        }
    }

    return false;
}

static int pico_cfg80211_get_psk(const struct cfg80211_connect_params* sme,
                                 const u8** psk, u8* psk_len) {
    const struct cfg80211_crypto_settings* crypto;

    if (!sme || !psk || !psk_len)
        return -EINVAL;

    *psk = NULL;
    *psk_len = 0;

    crypto = &sme->crypto;

    if (crypto->psk) {
        *psk = crypto->psk;
        *psk_len = 32;
        return 0;
    }

    if (sme->key && sme->key_len) {
        if (sme->key_len < 8 || sme->key_len > 64)
            return -EINVAL;
        *psk = sme->key;
        *psk_len = sme->key_len;
        return 0;
    }

    return -ENOENT;
}

static void pico_cfg80211_conn_work(struct work_struct* work) {
    struct pico_cfg80211* cfg = container_of(work, struct pico_cfg80211, conn_work);
    struct net_device* ndev;
    bool connected;
    bool was_connecting;
    bool was_connected;
    bool locally_generated;
    u8 bssid[ETH_ALEN];
    bool bssid_valid;

    if (!cfg || !cfg->wdev || !cfg->wdev->netdev)
        return;

    ndev = cfg->wdev->netdev;

    spin_lock_bh(&cfg->lock);
    connected = cfg->is_connected;
    was_connecting = cfg->connect_in_progress;
    was_connected = cfg->prev_connected;
    locally_generated = cfg->disconnect_requested;
    memcpy(bssid, cfg->bssid, ETH_ALEN);
    cfg->connect_in_progress = false;
    cfg->disconnect_requested = false;
    spin_unlock_bh(&cfg->lock);

    bssid_valid = !is_zero_ether_addr(bssid);

    if (was_connecting) {
        if (connected) {
            cfg80211_connect_result(ndev,
                                    bssid_valid ? bssid : NULL,
                                    NULL, 0,
                                    NULL, 0,
                                    WLAN_STATUS_SUCCESS,
                                    GFP_KERNEL);
            return;
        }
        cfg80211_connect_result(ndev,
                                NULL,
                                NULL, 0,
                                NULL, 0,
                                WLAN_STATUS_UNSPECIFIED_FAILURE,
                                GFP_KERNEL);
        return;
    }

    if (was_connected && !connected) {
        cfg80211_disconnected(ndev,
                              WLAN_REASON_UNSPECIFIED,
                              NULL, 0,
                              locally_generated,
                              GFP_KERNEL);
    }
}

static int pico_cfg80211_scan(struct wiphy* wiphy,
                              struct cfg80211_scan_request* request) {
    struct pico_cfg80211* cfg = wiphy_priv(wiphy);
    int ret;

    if (!cfg || !cfg->pdev)
        return -ENODEV;

    spin_lock_bh(&cfg->lock);
    if (cfg->scan_req) {
        spin_unlock_bh(&cfg->lock);
        return -EBUSY;
    }
    cfg->scan_req = request;
    spin_unlock_bh(&cfg->lock);

    ret = pico_ctrl_scan_start(cfg->pdev);
    if (ret) {
        spin_lock_bh(&cfg->lock);
        cfg->scan_req = NULL;
        spin_unlock_bh(&cfg->lock);
        return ret;
    }

    return 0;
}

static int pico_cfg80211_connect(struct wiphy* wiphy, struct net_device* dev,
                                 struct cfg80211_connect_params* sme) {
    struct pico_cfg80211* cfg = wiphy_priv(wiphy);
    const u8* ssid;
    u8 ssid_len;
    const u8* psk = NULL;
    u8 psk_len = 0;
    u8 key_type = PICO_KEY_NONE;
    bool want_psk = false;
    int psk_ret;
    int ret;

    (void)dev;

    if (!cfg || !cfg->pdev || !sme || !sme->ssid || sme->ssid_len == 0)
        return -EINVAL;

    ssid = sme->ssid;
    ssid_len = (u8)min_t(size_t, sme->ssid_len, 32);

    want_psk = pico_cfg80211_has_psk_akm(&sme->crypto) ||
               (sme->crypto.wpa_versions != 0) ||
               sme->privacy;

    psk_ret = pico_cfg80211_get_psk(sme, &psk, &psk_len);
    if (want_psk) {
        if (psk_ret == -ENOENT)
            return -EOPNOTSUPP;
        if (psk_ret)
            return psk_ret;
        key_type = (sme->crypto.psk != NULL) ? PICO_KEY_PMK : PICO_KEY_PASSPHRASE;
    } else {
        psk = NULL;
        psk_len = 0;
        key_type = PICO_KEY_NONE;
    }

    spin_lock_bh(&cfg->lock);
    if (cfg->connect_in_progress) {
        spin_unlock_bh(&cfg->lock);
        return -EBUSY;
    }
    if (cfg->is_connected) {
        spin_unlock_bh(&cfg->lock);
        return -EALREADY;
    }
    cfg->connect_in_progress = true;
    spin_unlock_bh(&cfg->lock);

    ret = pico_ctrl_connect(cfg->pdev, ssid, ssid_len, psk, psk_len, key_type);
    if (ret) {
        spin_lock_bh(&cfg->lock);
        cfg->connect_in_progress = false;
        spin_unlock_bh(&cfg->lock);
        return ret;
    }

    return 0;
}

static int pico_cfg80211_disconnect(struct wiphy* wiphy, struct net_device* dev,
                                    u16 reason_code) {
    struct pico_cfg80211* cfg = wiphy_priv(wiphy);
    int ret;

    (void)dev;
    (void)reason_code;

    if (!cfg || !cfg->pdev)
        return -ENODEV;

    spin_lock_bh(&cfg->lock);
    cfg->disconnect_requested = true;
    spin_unlock_bh(&cfg->lock);

    ret = pico_ctrl_disconnect(cfg->pdev);
    if (ret)
        return ret;

    return 0;
}

static int pico_cfg80211_get_station(struct wiphy* wiphy, struct net_device* dev,
                                     const u8* mac, struct station_info* sinfo) {
    struct pico_cfg80211* cfg = wiphy_priv(wiphy);

    (void)dev;
    (void)mac;

    if (!cfg)
        return -ENODEV;

    if (!cfg->is_connected)
        return -ENODEV;

    sinfo->filled = BIT_ULL(NL80211_STA_INFO_SIGNAL);
    sinfo->signal = cfg->rssi;
    return 0;
}

static int pico_cfg80211_add_key(struct wiphy* wiphy, struct net_device* dev,
                                 int link_id, u8 key_index, bool pairwise,
                                 const u8* mac_addr, struct key_params* params) {
    (void)wiphy;
    (void)dev;
    (void)link_id;
    (void)key_index;
    (void)pairwise;
    (void)mac_addr;
    (void)params;

    /*
     * FullMAC offload: CYW43 firmware handles WPA/WPA2 keying internally.
     * wpa_supplicant still programs keys via nl80211, so accept these calls.
     */
    return 0;
}

static int pico_cfg80211_del_key(struct wiphy* wiphy, struct net_device* dev,
                                 int link_id, u8 key_index, bool pairwise,
                                 const u8* mac_addr) {
    (void)wiphy;
    (void)dev;
    (void)link_id;
    (void)key_index;
    (void)pairwise;
    (void)mac_addr;
    return 0;
}

static int pico_cfg80211_set_default_key(struct wiphy* wiphy, struct net_device* dev,
                                         int link_id, u8 key_index, bool unicast, bool multicast) {
    (void)wiphy;
    (void)dev;
    (void)link_id;
    (void)key_index;
    (void)unicast;
    (void)multicast;
    return 0;
}

static int pico_cfg80211_set_default_mgmt_key(struct wiphy* wiphy, struct net_device* dev,
                                              int link_id, u8 key_index) {
    (void)wiphy;
    (void)dev;
    (void)link_id;
    (void)key_index;
    return 0;
}

static const struct cfg80211_ops pico_cfg80211_ops = {
    .scan = pico_cfg80211_scan,
    .connect = pico_cfg80211_connect,
    .disconnect = pico_cfg80211_disconnect,
    .get_station = pico_cfg80211_get_station,
    .add_key = pico_cfg80211_add_key,
    .del_key = pico_cfg80211_del_key,
    .set_default_key = pico_cfg80211_set_default_key,
    .set_default_mgmt_key = pico_cfg80211_set_default_mgmt_key,
};

struct pico_cfg80211* pico_cfg80211_init(struct pico_dev* pdev,
                                         struct net_device* ndev,
                                         struct device* dev) {
    struct wiphy* wiphy;
    struct pico_cfg80211* cfg;
    struct wireless_dev* wdev;
    static const u32 ciphers[] = {
        WLAN_CIPHER_SUITE_WEP40,
        WLAN_CIPHER_SUITE_WEP104,
        WLAN_CIPHER_SUITE_TKIP,
        WLAN_CIPHER_SUITE_CCMP,
    };

    if (!pdev || !ndev || !dev)
        return NULL;

    wiphy = wiphy_new(&pico_cfg80211_ops, sizeof(*cfg));
    if (!wiphy)
        return NULL;

    cfg = wiphy_priv(wiphy);
    memset(cfg, 0, sizeof(*cfg));
    cfg->wiphy = wiphy;
    cfg->pdev = pdev;
    spin_lock_init(&cfg->lock);
    INIT_WORK(&cfg->scan_done_work, pico_cfg80211_scan_done_work);
    INIT_WORK(&cfg->conn_work, pico_cfg80211_conn_work);

    set_wiphy_dev(wiphy, dev);
    wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION);
    wiphy->bands[NL80211_BAND_2GHZ] = &pico_band_2ghz;
    wiphy->signal_type = CFG80211_SIGNAL_TYPE_MBM;
    wiphy->max_scan_ssids = 4;
    wiphy->max_scan_ie_len = 0;
    wiphy->cipher_suites = ciphers;
    wiphy->n_cipher_suites = ARRAY_SIZE(ciphers);
    /*
     * CYW43 is FullMAC: it performs WPA(2)-PSK 4-way handshake internally.
     * Advertise STA PSK handshake offload so userspace provides PMK via
     * NL80211_ATTR_PMK in NL80211_CMD_CONNECT (surfaced as crypto->psk).
     */
    wiphy_ext_feature_set(wiphy, NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK);

    wdev = kzalloc(sizeof(*wdev), GFP_KERNEL);
    if (!wdev) {
        wiphy_free(wiphy);
        return NULL;
    }

    wdev->wiphy = wiphy;
    wdev->iftype = NL80211_IFTYPE_STATION;
    wdev->netdev = ndev;
    ndev->ieee80211_ptr = wdev;

    SET_NETDEV_DEV(ndev, wiphy_dev(wiphy));

    if (wiphy_register(wiphy)) {
        kfree(wdev);
        wiphy_free(wiphy);
        return NULL;
    }

    cfg->wdev = wdev;
    return cfg;
}

void pico_cfg80211_deinit(struct pico_cfg80211* cfg) {
    if (!cfg)
        return;

    cancel_work_sync(&cfg->scan_done_work);
    cancel_work_sync(&cfg->conn_work);

    if (cfg->wiphy)
        wiphy_unregister(cfg->wiphy);

    if (cfg->wdev)
        kfree(cfg->wdev);

    if (cfg->wiphy)
        wiphy_free(cfg->wiphy);
}

void pico_cfg80211_report_scan_result(struct pico_cfg80211* cfg,
                                      const u8* bssid,
                                      u8 channel,
                                      s8 rssi,
                                      u16 security,
                                      const char* ssid,
                                      u8 ssid_len) {
    struct ieee80211_channel* chan;
    struct cfg80211_inform_bss data = {};
    struct cfg80211_bss* bss;
    int freq;
    u16 capability = WLAN_CAPABILITY_ESS;
    u8 auth_mode = (u8)(security & 0xff);

    if (!cfg || !cfg->wiphy)
        return;

    freq = ieee80211_channel_to_frequency(channel, NL80211_BAND_2GHZ);
    chan = ieee80211_get_channel(cfg->wiphy, freq);
    if (!chan)
        return;

    data.chan = chan;
    data.signal = (s32)rssi * 100;
    data.boottime_ns = ktime_get_boottime_ns();

    {
        /* SSID IE + optional RSN/WPA IE */
        u8 ie[2 + 32 + 2 + 24];
        size_t ie_len = 0;
        bool privacy = (auth_mode & 0x01) != 0;

        if (ssid_len > 32)
            ssid_len = 32;
        ie[0] = WLAN_EID_SSID;
        ie[1] = ssid_len;
        if (ssid_len)
            memcpy(&ie[2], ssid, ssid_len);
        ie_len = 2 + ssid_len;

        if (privacy)
            capability |= WLAN_CAPABILITY_PRIVACY;

        /*
         * Firmware scan results only provide a compact auth code.
         * Map the common cases so wpa_supplicant can select WPA/WPA2 networks.
         */
        if (auth_mode & 0x04) {
            /* WPA2-PSK-CCMP RSN IE (minimal) */
            static const u8 rsn_ie[] = {
                WLAN_EID_RSN,
                20,
                0x01,
                0x00, /* Version 1 */
                0x00,
                0x0f,
                0xac,
                0x04, /* Group cipher: CCMP */
                0x01,
                0x00, /* Pairwise cipher count */
                0x00,
                0x0f,
                0xac,
                0x04, /* Pairwise cipher: CCMP */
                0x01,
                0x00, /* AKM count */
                0x00,
                0x0f,
                0xac,
                0x02, /* AKM: PSK */
                0x00,
                0x00, /* RSN capabilities */
            };
            memcpy(ie + ie_len, rsn_ie, sizeof(rsn_ie));
            ie_len += sizeof(rsn_ie);
        } else if (auth_mode & 0x02) {
            /* WPA-PSK-TKIP vendor IE (minimal) */
            static const u8 wpa_ie[] = {
                WLAN_EID_VENDOR_SPECIFIC,
                22,
                0x00,
                0x50,
                0xf2,
                0x01, /* OUI + type */
                0x01,
                0x00, /* Version 1 */
                0x00,
                0x50,
                0xf2,
                0x02, /* Group cipher: TKIP */
                0x01,
                0x00, /* Pairwise cipher count */
                0x00,
                0x50,
                0xf2,
                0x02, /* Pairwise cipher: TKIP */
                0x01,
                0x00, /* AKM count */
                0x00,
                0x50,
                0xf2,
                0x02, /* AKM: PSK */
            };
            memcpy(ie + ie_len, wpa_ie, sizeof(wpa_ie));
            ie_len += sizeof(wpa_ie);
        }

        bss = cfg80211_inform_bss_data(cfg->wiphy, &data,
                                       CFG80211_BSS_FTYPE_PRESP,
                                       bssid, 0, capability, 100,
                                       ie, ie_len, GFP_ATOMIC);
    }
    if (bss)
        cfg80211_put_bss(cfg->wiphy, bss);
}

void pico_cfg80211_scan_done(struct pico_cfg80211* cfg, bool aborted) {
    if (!cfg)
        return;
    spin_lock_bh(&cfg->lock);
    if (!cfg->scan_req) {
        spin_unlock_bh(&cfg->lock);
        return;
    }
    cfg->scan_aborted = aborted;
    spin_unlock_bh(&cfg->lock);

    schedule_work(&cfg->scan_done_work);
}

void pico_cfg80211_conn_state(struct pico_cfg80211* cfg,
                              bool connected,
                              const u8* bssid,
                              const char* ssid,
                              u8 ssid_len,
                              u16 status,
                              s8 rssi,
                              u8 channel) {
    if (!cfg)
        return;
    spin_lock_bh(&cfg->lock);
    cfg->prev_connected = cfg->is_connected;
    cfg->is_connected = connected;
    cfg->ssid_len = ssid_len;
    memcpy(cfg->ssid, ssid, sizeof(cfg->ssid));
    memcpy(cfg->bssid, bssid, ETH_ALEN);
    cfg->status = status;
    cfg->rssi = rssi;
    cfg->channel = channel;
    spin_unlock_bh(&cfg->lock);

    if (connected && !is_zero_ether_addr(bssid) && channel > 0) {
        pico_cfg80211_report_scan_result(cfg, bssid, channel, rssi, 0,
                                         ssid, ssid_len);
    }

    schedule_work(&cfg->conn_work);
}
