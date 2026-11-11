/*
 * This file is part of AtomVM.
 *
 * Copyright 2026 Gabriel Mancini <gabriel.mancini@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0 OR LGPL-2.1-or-later
 */

#include <sdkconfig.h>
#ifdef CONFIG_AVM_ENABLE_ESPNOW

#include <stdlib.h>
#include <string.h>

#include <dhcpserver/dhcpserver.h>
#include <esp_log.h>
#include <esp_netif.h>
#include <esp_netif_defaults.h>
#include <esp_netif_net_stack.h>
#include <esp_now.h>
#include <esp_timer.h>
#include <esp_wifi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <lwip/dns.h>
#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/tcpip.h>

#include "utils.h"

#include <espnow_tunnel.h>

#define TAG "espnow_tunnel"

#ifdef ESP_NOW_MAX_DATA_LEN_V2

// The first byte of a tunnel frame. Other frames are the application's.
#define TUNNEL_BEACON 0xA5
#define TUNNEL_FRAME 0xA6
#define MAC_LEN 6
// A gateway's: {TUNNEL_BEACON, 'i', 'b', 1, Channel}.
#define BEACON_LEN 5
// A relay's: {TUNNEL_BEACON, 'i', 'b', 2, Channel, Depth, ParentMac:6}, Depth
// the hops to the gateway (1 for a relay on a gateway) and ParentMac the
// gateway or relay it goes out by.
#define RELAY_BEACON_LEN (BEACON_LEN + 1 + MAC_LEN)
// A beacon this deep is not followed: a loop of relays that lost their way
// out counts up to it and breaks.
#define MAX_DEPTH 4
#define ETH_HEADER_LEN 14
#define TUNNEL_MTU (ESP_NOW_MAX_DATA_LEN_V2 - 1 - ETH_HEADER_LEN)
#define TICK_US (200 * 1000)
// The gateway announces itself each tick, a node listens two ticks per channel:
// a pass over the 13 channels takes 5.2 s.
#define HOP_TICKS 2
#define MAX_CHANNEL 13
#define LOST_US (5 * 1000 * 1000)
#define ROUTE_PRIO 5
// A relay's netif for its own nodes: below the way out, which stays the
// default route.
#define DOWN_ROUTE_PRIO 1

struct Tunnel;

struct TunnelGlue
{
    esp_netif_driver_base_t base;
    struct Tunnel *tunnel;
};

struct Tunnel
{
    struct TunnelGlue glue;
    enum EspNowTunnelRole role;
    espnow_tunnel_notify notify;
    esp_netif_t *netif;
    struct netif *lwip;
    esp_timer_handle_t timer;
    // Held by a tick while it runs, so that stop waits for it.
    SemaphoreHandle_t tick_lock;
    SemaphoreHandle_t drained;
    volatile bool running;
    // A node's state. `heard' and `last_heard' come from the receive callback
    // (Wi-Fi task), the rest is the timer's.
    volatile bool heard;
    uint8_t heard_mac[MAC_LEN];
    uint8_t heard_channel;
    volatile int64_t last_heard;
    uint8_t heard_depth;
    volatile bool locked;
    bool has_ip;
    uint8_t gateway[MAC_LEN];
    uint8_t depth;
    uint8_t channel;
    unsigned ticks;
    uint8_t mac[MAC_LEN];
    // A relay's netif for its own nodes, open while it has an address: the
    // receive callback reads `down_lwip' while `down_up'.
    struct TunnelGlue down_glue;
    esp_netif_t *down_netif;
    struct netif *volatile down_lwip;
    volatile bool down_up;
    struct EspNowTunnelStats stats;
    // Only lwIP's output uses it, one frame at a time.
    uint8_t tx[ESP_NOW_MAX_DATA_LEN_V2];
};

static struct Tunnel *tunnel;

static const uint8_t broadcast_mac[MAC_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

// lwIP's output (the TCP/IP task, or a caller holding the core lock): an
// Ethernet frame, sent to the ESP-NOW peer with its destination address.
static esp_err_t tunnel_transmit(void *handle, void *buffer, size_t len)
{
    struct Tunnel *t = handle;
    if (UNLIKELY(len < ETH_HEADER_LEN || len > ETH_HEADER_LEN + TUNNEL_MTU)) {
        return ESP_ERR_INVALID_SIZE;
    }
    const uint8_t *destination = buffer;
    // Broadcast and multicast (the group bit) go to every node.
    const uint8_t *to = (destination[0] & 1) ? broadcast_mac : destination;
    if (to != broadcast_mac && !esp_now_is_peer_exist(to)) {
        esp_now_peer_info_t peer = { .channel = 0, .ifidx = WIFI_IF_STA };
        memcpy(peer.peer_addr, to, MAC_LEN);
        esp_err_t err = esp_now_add_peer(&peer);
        if (UNLIKELY(err != ESP_OK)) {
            ESP_LOGW(TAG, "No peer for a tunnel frame: %s", esp_err_to_name(err));
            t->stats.tx_fail++;
            return err;
        }
    }
    t->tx[0] = TUNNEL_FRAME;
    memcpy(t->tx + 1, buffer, len);
    esp_err_t err = esp_now_send(to, t->tx, len + 1);
    if (err == ESP_OK) {
        t->stats.tx++;
    } else if (t->stats.tx_fail++ == 0) {
        ESP_LOGW(TAG, "Failed to send a tunnel frame of %u bytes: %s", (unsigned) len + 1, esp_err_to_name(err));
    }
    return err;
}

static void tunnel_free_rx(void *handle, void *buffer)
{
    (void) handle;
    free(buffer);
}

static esp_err_t tunnel_post_attach(esp_netif_t *netif, void *args)
{
    struct TunnelGlue *glue = args;
    glue->base.netif = netif;
    const esp_netif_driver_ifconfig_t driver = {
        .handle = glue->tunnel,
        .transmit = tunnel_transmit,
        .driver_free_rx_buffer = tunnel_free_rx
    };
    return esp_netif_set_driver_config(netif, &driver);
}

// A gateway's beacon is depth 0. A relay's is followed unless it goes out by
// this board (one of its own nodes, which still beacons for a while after
// this board lost its way out) or it is too deep.
static void hear_beacon(struct Tunnel *t, const uint8_t *from, const uint8_t *data, int len)
{
    uint8_t depth;
    if (len == BEACON_LEN && memcmp(data + 1, "ib\x01", 3) == 0) {
        depth = 0;
    } else if (len == RELAY_BEACON_LEN && memcmp(data + 1, "ib\x02", 3) == 0
        && data[5] < MAX_DEPTH && memcmp(data + 6, t->mac, MAC_LEN) != 0) {
        depth = data[5];
    } else {
        return;
    }
    memcpy(t->heard_mac, from, MAC_LEN);
    t->heard_channel = data[4];
    t->heard_depth = depth;
    t->heard = true;
}

bool espnow_tunnel_receive(const esp_now_recv_info_t *info, const uint8_t *data, int len)
{
    struct Tunnel *t = tunnel;
    if (t == NULL || !t->running || len < 1 || (data[0] != TUNNEL_BEACON && data[0] != TUNNEL_FRAME)) {
        return false;
    }
    t->stats.heard++;
    // A relay goes out like a node, and is a gateway to its own nodes.
    bool node = t->role != EspNowTunnelGateway;
    bool from_gateway = node && t->locked && memcmp(info->src_addr, t->gateway, MAC_LEN) == 0;
    if (from_gateway) {
        t->last_heard = esp_timer_get_time();
    }

    if (data[0] == TUNNEL_BEACON) {
        if (node && !t->locked && !t->heard) {
            hear_beacon(t, info->src_addr, data, len);
        }
        return true;
    }

    // A node takes frames from its gateway only; the gateway, from any node;
    // a relay, those from its gateway into its way out, the others into its
    // own nodes' netif.
    struct netif *lwip = t->lwip;
    if (!from_gateway && t->role == EspNowTunnelRelay) {
        lwip = t->down_up ? t->down_lwip : NULL;
    } else if (node && !from_gateway) {
        lwip = NULL;
    }
    if (len - 1 < ETH_HEADER_LEN || lwip == NULL || !netif_is_up(lwip)) {
        t->stats.rx_drop++;
        return true;
    }
    // Copied, not handed as a custom pbuf that points at the netif: a socket
    // can hold a received pbuf after the tunnel is gone.
    struct pbuf *p = pbuf_alloc(PBUF_RAW, len - 1, PBUF_RAM);
    if (UNLIKELY(p == NULL)) {
        t->stats.rx_drop++;
        return true;
    }
    memcpy(p->payload, data + 1, len - 1);
    if (lwip->input(p, lwip) != ERR_OK) {
        pbuf_free(p);
        t->stats.rx_drop++;
        return true;
    }
    t->stats.rx++;
    return true;
}

static void gateway_tick(struct Tunnel *t)
{
    (void) t;
    uint8_t primary;
    wifi_second_chan_t second;
    if (esp_wifi_get_channel(&primary, &second) == ESP_OK) {
        const uint8_t beacon[BEACON_LEN] = { TUNNEL_BEACON, 'i', 'b', 1, primary };
        esp_now_send(broadcast_mac, beacon, BEACON_LEN);
    }
}

static void tunnel_drained(void *arg)
{
    xSemaphoreGive((SemaphoreHandle_t) arg);
}

// The DNS server the nodes are offered: the gateway's own, as it is now.
static void gateway_offer_dns(esp_netif_t *netif)
{
    esp_netif_dns_info_t dns = { .ip.type = ESP_IPADDR_TYPE_V4 };
    const ip_addr_t *server = dns_getserver(0);
    if (server != NULL && IP_IS_V4(server) && !ip_addr_isany(server)) {
        dns.ip.u_addr.ip4.addr = ip_2_ip4(server)->addr;
    } else {
        dns.ip.u_addr.ip4.addr = ESP_IP4TOADDR(8, 8, 8, 8);
    }
    dhcps_offer_t offer = OFFER_DNS;
    if (esp_netif_set_dns_info(netif, ESP_NETIF_DNS_MAIN, &dns) != ESP_OK
        || esp_netif_dhcps_option(netif, ESP_NETIF_OP_SET, ESP_NETIF_DOMAIN_NAME_SERVER, &offer, sizeof(offer)) != ESP_OK) {
        ESP_LOGW(TAG, "The nodes get no DNS server");
    }
}

// A netif of the tunnel, on the station's MAC. The side that serves nodes (a
// gateway's, or a relay's for its own nodes) is `address'/24, leases the rest
// and NATs them out; the other asks its gateway by DHCP.
static esp_err_t new_netif(struct Tunnel *t, struct TunnelGlue *glue, bool serves, uint32_t address,
    const char *key, int route_prio, esp_netif_t **out)
{
    esp_netif_ip_info_t ip = { 0 };
    if (serves) {
        ip.ip.addr = address;
        ip.gw.addr = address;
        ip.netmask.addr = ESP_IP4TOADDR(255, 255, 255, 0);
    }
    esp_netif_inherent_config_t base = {
        .flags = serves ? (ESP_NETIF_DHCP_SERVER | ESP_NETIF_FLAG_AUTOUP) : ESP_NETIF_DHCP_CLIENT,
        .ip_info = &ip,
        .if_key = key,
        .if_desc = "espnow",
        .route_prio = route_prio
    };
    memcpy(base.mac, t->mac, MAC_LEN);
    esp_netif_config_t config = { .base = &base, .stack = ESP_NETIF_NETSTACK_DEFAULT_ETH };
    esp_netif_t *netif = esp_netif_new(&config);
    if (netif == NULL) {
        return ESP_ERR_NO_MEM;
    }
    glue->base.post_attach = tunnel_post_attach;
    glue->tunnel = t;
    if (serves) {
        gateway_offer_dns(netif);
    }
    esp_err_t err = esp_netif_attach(netif, glue);
    if (err != ESP_OK) {
        esp_netif_destroy(netif);
        return err;
    }

    esp_netif_action_start(netif, NULL, 0, NULL);
    // Before any traffic. The Ethernet stack leaves lwIP's hardware address
    // zero, for the driver to set (DHCP would ask with it), and TCP takes its
    // MSS from the MTU at connect.
    esp_netif_set_mac(netif, base.mac);
    ((struct netif *) esp_netif_get_netif_impl(netif))->mtu = TUNNEL_MTU;
#ifdef CONFIG_LWIP_IPV4_NAPT
    if (serves && (err = esp_netif_napt_enable(netif)) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to enable NAT: %s", esp_err_to_name(err));
        esp_netif_action_stop(netif, NULL, 0, NULL);
        esp_netif_destroy(netif);
        return err;
    }
#endif
    *out = netif;
    return ESP_OK;
}

// Stops a netif whose input the receive callback may be handing to lwIP: a
// callback that saw it running finishes, and the frames it handed wait in the
// TCP/IP task's mailbox, which is FIFO, so a callback through it waits them
// out before the netif goes. False when the netif had to be left allocated.
static bool drain_and_destroy(struct Tunnel *t, esp_netif_t *netif, bool serves)
{
#ifdef CONFIG_LWIP_IPV4_NAPT
    if (serves) {
        esp_netif_napt_disable(netif);
    }
#else
    (void) serves;
#endif
    esp_netif_action_stop(netif, NULL, 0, NULL);
    vTaskDelay(pdMS_TO_TICKS(10));
    if (tcpip_callback(tunnel_drained, t->drained) != ERR_OK) {
        ESP_LOGE(TAG, "Failed to drain the tunnel's input, left allocated");
        return false;
    }
    xSemaphoreTake(t->drained, portMAX_DELAY);
    esp_netif_destroy(netif);
    return true;
}

// A relay with an address opens its own nodes' netif on a /24 of its own,
// 10.42.N.0 with N from its MAC, and never its gateway's.
static void relay_open(struct Tunnel *t, const esp_netif_ip_info_t *ip)
{
    if (t->role != EspNowTunnelRelay || t->down_netif != NULL) {
        return;
    }
    uint8_t upstream = (ip->ip.addr >> 16) & 0xFF;
    uint8_t n = 1 + t->mac[5] % 254;
    if (n == upstream) {
        n = n % 254 + 1;
    }
    esp_err_t err = new_netif(t, &t->down_glue, true, ESP_IP4TOADDR(10, 42, n, 1), "ESPNOW_DOWN", DOWN_ROUTE_PRIO, &t->down_netif);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open the relay's nodes' netif: %s", esp_err_to_name(err));
        t->down_netif = NULL;
        return;
    }
    t->down_lwip = esp_netif_get_netif_impl(t->down_netif);
    t->down_up = true;
    ESP_LOGI(TAG, "Relay open on 10.42.%u.1, %u hop(s) from the gateway", n, t->depth);
}

// A relay that lost its way out closes its nodes' netif and stops its beacon,
// so that they look for another.
static void relay_close(struct Tunnel *t)
{
    if (t->down_netif == NULL) {
        return;
    }
    t->down_up = false;
    if (drain_and_destroy(t, t->down_netif, true)) {
        ESP_LOGI(TAG, "Relay closed");
    }
    t->down_netif = NULL;
    t->down_lwip = NULL;
}

static void relay_beacon(struct Tunnel *t)
{
    uint8_t beacon[RELAY_BEACON_LEN] = { TUNNEL_BEACON, 'i', 'b', 2, t->channel, t->depth };
    memcpy(beacon + BEACON_LEN + 1, t->gateway, MAC_LEN);
    esp_now_send(broadcast_mac, beacon, RELAY_BEACON_LEN);
}

static void node_notify(struct Tunnel *t, enum EspNowTunnelEventKind kind, const esp_netif_ip_info_t *ip)
{
    struct EspNowTunnelEvent event = { .kind = kind, .channel = t->channel };
    memcpy(event.mac, t->gateway, MAC_LEN);
    if (ip != NULL) {
        event.ip = *ip;
    }
    t->notify(&event);
}

static void node_tick(struct Tunnel *t)
{
    int64_t now = esp_timer_get_time();
    if (!t->locked) {
        if (t->heard) {
            // The beacon carries the gateway's channel. Near the gateway a node
            // hears it on a neighbouring channel too, where farther away the
            // two would hardly hear each other: move to the gateway's.
            uint8_t channel = t->heard_channel;
            if (channel >= 1 && channel <= MAX_CHANNEL && channel != t->channel) {
                t->channel = channel;
                esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
            }
            memcpy(t->gateway, t->heard_mac, MAC_LEN);
            t->depth = t->heard_depth + 1;
            t->heard = false;
            t->has_ip = false;
            t->last_heard = now;
            t->locked = true;
            esp_netif_action_connected(t->netif, NULL, 0, NULL);
            node_notify(t, EspNowTunnelUp, NULL);
        } else if (++t->ticks % HOP_TICKS == 0) {
            t->channel = t->channel % MAX_CHANNEL + 1;
            esp_wifi_set_channel(t->channel, WIFI_SECOND_CHAN_NONE);
        }
        return;
    }
    if (now - t->last_heard > LOST_US) {
        t->locked = false;
        relay_close(t);
        esp_netif_action_disconnected(t->netif, NULL, 0, NULL);
        node_notify(t, EspNowTunnelDown, NULL);
        return;
    }
    esp_netif_ip_info_t ip;
    if (!t->has_ip && esp_netif_get_ip_info(t->netif, &ip) == ESP_OK && ip.ip.addr != 0) {
        t->has_ip = true;
        relay_open(t, &ip);
        node_notify(t, EspNowTunnelGotIp, &ip);
    }
    if (t->down_up) {
        relay_beacon(t);
    }
}

// esp_timer task.
static void tunnel_tick(void *arg)
{
    struct Tunnel *t = arg;
    if (xSemaphoreTake(t->tick_lock, 0) != pdTRUE) {
        return;
    }
    if (t->running) {
        if (t->role == EspNowTunnelGateway) {
            gateway_tick(t);
        } else {
            node_tick(t);
        }
    }
    xSemaphoreGive(t->tick_lock);
}

static void tunnel_free(struct Tunnel *t)
{
    if (t->tick_lock != NULL) {
        vSemaphoreDelete(t->tick_lock);
    }
    if (t->drained != NULL) {
        vSemaphoreDelete(t->drained);
    }
    free(t);
}

esp_err_t espnow_tunnel_start(enum EspNowTunnelRole role, espnow_tunnel_notify notify)
{
    uint32_t version;
    if (tunnel != NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    if (esp_now_get_version(&version) != ESP_OK || version < 2) {
        ESP_LOGE(TAG, "The tunnel needs ESP-NOW v2");
        return ESP_ERR_NOT_SUPPORTED;
    }
#ifndef CONFIG_LWIP_IPV4_NAPT
    if (role != EspNowTunnelNode) {
        ESP_LOGE(TAG, "A tunnel gateway or relay needs CONFIG_LWIP_IPV4_NAPT");
        return ESP_ERR_NOT_SUPPORTED;
    }
#endif

    struct Tunnel *t = calloc(1, sizeof(struct Tunnel));
    if (t == NULL) {
        return ESP_ERR_NO_MEM;
    }
    t->role = role;
    t->notify = notify;
    t->tick_lock = xSemaphoreCreateMutex();
    t->drained = xSemaphoreCreateBinary();
    if (t->tick_lock == NULL || t->drained == NULL) {
        tunnel_free(t);
        return ESP_ERR_NO_MEM;
    }

    esp_err_t err = esp_wifi_get_mac(WIFI_IF_STA, t->mac);
    if (err != ESP_OK) {
        tunnel_free(t);
        return err;
    }
    // The gateway is 10.42.0.1/24 and leases the rest; a node, and a relay on
    // its way out, ask their gateway by DHCP.
    bool gateway = role == EspNowTunnelGateway;
    if ((err = new_netif(t, &t->glue, gateway, ESP_IP4TOADDR(10, 42, 0, 1), "ESPNOW_DEF", ROUTE_PRIO, &t->netif)) != ESP_OK) {
        tunnel_free(t);
        return err;
    }
    t->lwip = esp_netif_get_netif_impl(t->netif);

    const esp_timer_create_args_t timer = { .callback = tunnel_tick, .arg = t, .name = "espnow_tunnel" };
    if ((err = esp_timer_create(&timer, &t->timer)) != ESP_OK) {
        esp_netif_action_stop(t->netif, NULL, 0, NULL);
        esp_netif_destroy(t->netif);
        tunnel_free(t);
        return err;
    }
    uint8_t primary;
    wifi_second_chan_t second;
    t->channel = esp_wifi_get_channel(&primary, &second) == ESP_OK ? primary : 1;
    t->running = true;
    tunnel = t;
    esp_timer_start_periodic(t->timer, TICK_US);
    ESP_LOGI(TAG, "Tunnel %s started", gateway ? "gateway" : (role == EspNowTunnelRelay ? "relay" : "node"));
    return ESP_OK;
}

void espnow_tunnel_stop(void)
{
    struct Tunnel *t = tunnel;
    if (t == NULL) {
        return;
    }
    t->running = false;
    xSemaphoreTake(t->tick_lock, portMAX_DELAY);
    esp_timer_stop(t->timer);
    esp_timer_delete(t->timer);
    xSemaphoreGive(t->tick_lock);
    tunnel = NULL;
    relay_close(t);
    if (!drain_and_destroy(t, t->netif, t->role == EspNowTunnelGateway)) {
        return;
    }
    tunnel_free(t);
    ESP_LOGI(TAG, "Tunnel stopped");
}

bool espnow_tunnel_active(void)
{
    return tunnel != NULL;
}

void espnow_tunnel_sent(bool ok)
{
    struct Tunnel *t = tunnel;
    if (t != NULL && !ok) {
        t->stats.nack++;
    }
}

bool espnow_tunnel_stats(struct EspNowTunnelStats *stats)
{
    struct Tunnel *t = tunnel;
    if (t == NULL) {
        return false;
    }
    *stats = t->stats;
    return true;
}

#else

esp_err_t espnow_tunnel_start(enum EspNowTunnelRole role, espnow_tunnel_notify notify)
{
    (void) role;
    (void) notify;
    ESP_LOGE(TAG, "The tunnel needs ESP-NOW v2 (ESP-IDF 5.4 or newer)");
    return ESP_ERR_NOT_SUPPORTED;
}

void espnow_tunnel_stop(void)
{
}

bool espnow_tunnel_active(void)
{
    return false;
}

void espnow_tunnel_sent(bool ok)
{
    (void) ok;
}

bool espnow_tunnel_stats(struct EspNowTunnelStats *stats)
{
    (void) stats;
    return false;
}

bool espnow_tunnel_receive(const esp_now_recv_info_t *info, const uint8_t *data, int len)
{
    (void) info;
    (void) data;
    (void) len;
    return false;
}

#endif
#endif
