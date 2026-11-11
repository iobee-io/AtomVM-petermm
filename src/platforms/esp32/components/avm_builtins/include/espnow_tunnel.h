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

#ifndef _ESPNOW_TUNNEL_H_
#define _ESPNOW_TUNNEL_H_

#include <stdbool.h>
#include <stdint.h>

#include <esp_err.h>
#include <esp_netif_ip_addr.h>
#include <esp_now.h>

/*
 * IP over ESP-NOW. Each frame carries an Ethernet frame, addressed with the
 * stations' MAC addresses, into a netif of its own:
 *
 *   - the gateway, on a board with a network, gives the nodes addresses
 *     (DHCP server) and NATs them out through its default route, and
 *     announces itself in broadcast on its channel;
 *   - a node, with no network, hops the channels until it hears a gateway,
 *     stays on its channel and gets an address from it. When the gateway is
 *     not heard for a while it goes down and hops again;
 *   - a relay goes out like a node and, once it has an address, is a
 *     gateway to nodes farther away: a netif of its own on 10.42.N.0/24, N
 *     from its MAC, NATed out through its way out, and a beacon one hop
 *     deeper. A node or relay follows the first gateway or relay it hears,
 *     never a relay that goes out by itself, nor one 4 hops deep.
 *
 * The gateway's and a relay's beacons carry a number drawn each time they
 * open: a node that hears its own with another number goes down at once, as
 * the NAT its sessions went through is gone, even when the restart took less
 * than the 5 s that make a gateway lost.
 *
 * Needs ESP-NOW v2 (ESP-IDF 5.4 or newer), whose 1470-byte frames fit an
 * Ethernet frame; the gateway and a relay also need CONFIG_LWIP_IPV4_NAPT.
 */

enum EspNowTunnelRole
{
    EspNowTunnelNode,
    EspNowTunnelGateway,
    EspNowTunnelRelay
};

enum EspNowTunnelEventKind
{
    EspNowTunnelUp,
    EspNowTunnelDown,
    EspNowTunnelGotIp
};

struct EspNowTunnelEvent
{
    enum EspNowTunnelEventKind kind;
    uint8_t mac[6];
    uint8_t channel;
    esp_netif_ip_info_t ip;
};

struct EspNowTunnelStats
{
    uint32_t tx;
    uint32_t tx_fail;
    uint32_t rx;
    uint32_t rx_drop;
    uint32_t nack;
    uint32_t heard;
};

// Delivered from the tunnel's timer task; the callee queues it.
typedef void (*espnow_tunnel_notify)(const struct EspNowTunnelEvent *event);

// Called after esp_now_init, in the scheduler.
esp_err_t espnow_tunnel_start(enum EspNowTunnelRole role, espnow_tunnel_notify notify);
// Called before esp_now_deinit, in the scheduler; waits for the netif's queued input.
void espnow_tunnel_stop(void);
bool espnow_tunnel_active(void);
// From the ESP-NOW send callback (Wi-Fi task).
void espnow_tunnel_sent(bool ok);
// False without a tunnel.
bool espnow_tunnel_stats(struct EspNowTunnelStats *stats);
// From the ESP-NOW receive callback (Wi-Fi task): true when the frame was the tunnel's.
bool espnow_tunnel_receive(const esp_now_recv_info_t *info, const uint8_t *data, int len);

#endif
