%
% This file is part of AtomVM.
%
% Copyright 2026 Gabriel Mancini <gabriel.mancini@gmail.com>
%
% The API follows harmon25/atomvm_espnow (Apache-2.0).
%
% Licensed under the Apache License, Version 2.0 (the "License");
% you may not use this file except in compliance with the License.
% You may obtain a copy of the License at
%
%    http://www.apache.org/licenses/LICENSE-2.0
%
% Unless required by applicable law or agreed to in writing, software
% distributed under the License is distributed on an "AS IS" BASIS,
% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
% See the License for the specific language governing permissions and
% limitations under the License.
%
% SPDX-License-Identifier: Apache-2.0 OR LGPL-2.1-or-later
%

%%-----------------------------------------------------------------------------
%% @doc ESP-NOW: connectionless frames of up to 250 bytes between ESP32
%% devices, on the Wi-Fi radio, with no access point.
%%
%% Needs `CONFIG_AVM_ENABLE_ESPNOW'. The network driver owns the radio: ESP-NOW
%% works with or without a network, and survives `network:stop/0' and
%% `network:start/1'. With the STA connected, frames go on the access point's
%% channel; otherwise on the channel given to `open/1' or `set_channel/2'.
%%
%% The receiver (the caller of `open/1' unless `{receiver, Pid}') gets
%% `{espnow, rx, Mac, Data, #{rssi := Rssi}}' for each frame, and
%% `{espnow, sent, Mac, ok | fail}' for each `send/3': for a unicast frame
%% `ok' means the peer acknowledged it, for a broadcast only that it went out.
%%
%% With `{tunnel, Role}', the port also carries IP: a netif of its own, whose
%% Ethernet frames travel in ESP-NOW frames (ESP-NOW v2, ESP-IDF 5.4 or newer).
%% A `gateway', on a board with a network, is 10.42.0.1/24, leases addresses
%% to the nodes, NATs them out through its default route (it needs
%% `CONFIG_LWIP_IPV4_NAPT') and announces itself on its channel. A `node' hops
%% the channels until it hears a gateway, stays on its channel and asks it for
%% an address. The receiver gets `{espnow, tunnel, {up, GatewayMac, Channel}}',
%% `{espnow, tunnel, {got_ip, {Address, Netmask, Gateway}}}', and
%% `{espnow, tunnel, down}' when the gateway has not been heard for 5 s (the
%% node then hops again). A `relay' goes out like a node and, with an
%% address, is a gateway to nodes farther away: 10.42.N.0/24 of its own (N
%% from its MAC), NATed out through its gateway, announced one hop deeper. A
%% node or relay follows the first gateway or relay it hears, but never a
%% relay that goes out by itself, nor one 4 hops deep; its receiver gets the
%% node's messages. Frames whose first byte is 16#A5 or 16#A6 are the
%% tunnel's, and with a tunnel no `sent' result is reported.
%% @end
%%-----------------------------------------------------------------------------
-module(espnow).

-export([
    open/0, open/1,
    close/1,
    add_peer/2, add_peer/3,
    del_peer/2,
    send/3,
    set_channel/2,
    get_channel/1,
    stats/1
]).

-type mac() :: <<_:48>>.
%% A peer's station MAC address.
-type channel() :: 0..14.
%% A Wi-Fi channel; 0 is the current one.
-type key() :: <<_:128>>.

-type open_option() ::
    {receiver, pid()}
    | {channel, channel()}
    | {pmk, key()}
    | {tunnel, node | gateway | relay}.
%% `pmk' is the primary key that encrypts the peers' `lmk' keys.

-type peer_option() :: {channel, channel()} | {lmk, key()}.
%% `lmk' encrypts the traffic with this peer (at most 6 encrypted peers).

-export_type([mac/0, channel/0]).

%% @equiv open([])
-spec open() -> {ok, port()} | {error, term()}.
open() ->
    open([]).

%% @doc Starts ESP-NOW, turning the Wi-Fi radio on if no network has it.
%% Only one port can be open.
-spec open([open_option()]) -> {ok, port()} | {error, term()}.
open(Options) ->
    Receiver = proplists:get_value(receiver, Options, self()),
    try open_port({spawn, "espnow"}, [{receiver, Receiver} | proplists:delete(receiver, Options)]) of
        Port -> {ok, Port}
    catch
        error:Reason -> {error, Reason}
    end.

%% @doc Stops ESP-NOW; the radio goes off if no network uses it.
-spec close(port()) -> ok.
close(Port) ->
    port:call(Port, close).

%% @equiv add_peer(Port, Mac, [])
-spec add_peer(port(), mac()) -> ok | {error, term()}.
add_peer(Port, Mac) ->
    add_peer(Port, Mac, []).

%% @doc Adds a unicast peer. Broadcast needs no peer.
-spec add_peer(port(), mac(), [peer_option()]) -> ok | {error, term()}.
add_peer(Port, Mac, Options) ->
    port:call(Port, {add_peer, Mac, Options}).

-spec del_peer(port(), mac()) -> ok | {error, term()}.
del_peer(Port, Mac) ->
    port:call(Port, {del_peer, Mac}).

%% @doc Queues `Data' (1 to 250 bytes) for `Mac', a peer, or `broadcast'. The
%% result comes to the receiver as `{espnow, sent, Mac, ok | fail}'.
-spec send(port(), mac() | broadcast, binary()) -> ok | {error, term()}.
send(Port, Mac, Data) ->
    port:call(Port, {send, Mac, Data}).

%% @doc Moves to `Channel' (1 to 14). Fails while the STA is connected, whose
%% channel is the access point's.
-spec set_channel(port(), 1..14) -> ok | {error, term()}.
set_channel(Port, Channel) ->
    port:call(Port, {set_channel, Channel}).

-spec get_channel(port()) -> {ok, 1..14} | {error, term()}.
get_channel(Port) ->
    port:call(Port, get_channel).

%% @doc `dropped': frames and send results lost because the receiver did not
%% keep up (the driver queues 8).
-spec stats(port()) -> {ok, #{dropped := non_neg_integer()}}.
stats(Port) ->
    port:call(Port, stats).
