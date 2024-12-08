/*
 * Copyright 2018 The Polycube Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <tins/ethernetII.h>
#include <openssl/evp.h>
#include <linux/ip.h> // iphdr
#include <linux/ipv6.h> //ipv6hdr
#include <linux/udp.h> // udphdr
#include <linux/tcp.h> // tcphdr
#include <linux/icmp.h> // icmphdr
#include <linux/icmpv6.h> // icmp6hdr
#include <arpa/inet.h> //ntohs
#include <net/ethernet.h>

#include "../base/HelloworldBase.h"

#include "Ports.h"

using namespace polycube::service::model;

class Helloworld : public HelloworldBase {
 public:
  Helloworld(const std::string name, const HelloworldJsonObject &conf);
  virtual ~Helloworld();

  void packet_in(Ports &port, polycube::service::PacketInMetadata &md,
                 const std::vector<uint8_t> &packet) override;

  /// <summary>
  /// Entry of the ports table
  /// </summary>
  void addPorts(const std::string &name, const PortsJsonObject &conf) override;
  void delPorts(const std::string &name) override;

  /// <summary>
  /// Action performed on the received packet (i.e., DROP, SLOWPATH, or FORWARD; default: DROP)
  /// </summary>
  HelloworldActionEnum getAction() override;
  void setAction(const HelloworldActionEnum &value) override;
 private:
  // saves the indexes in the ports maps used when action is forward
  void update_ports_map();
  void swap_mac_addresses(void *pkt);
  int setup_rule();
};
