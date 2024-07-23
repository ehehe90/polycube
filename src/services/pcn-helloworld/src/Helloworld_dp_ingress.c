/*
 * Copyright 2017 The Polycube Authors
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

// WARNING: log messages from this program are used by programs_chain tests,
//          changing them may cause those tests to fail

/*
 * This file contains the eBPF code that implements the service datapath.
 * Of course it is no required to have this into a separated file, however
 * it could be a good idea in order to better organize the code.
 */

#include <bcc/helpers.h>
#include <bcc/proto.h>
#include <uapi/linux/if_ether.h>
#include <linux/ip.h> // iphdr
#include <linux/ipv6.h> //ipv6hdr
#include <linux/udp.h> // udphdr
#include <linux/tcp.h> // tcphdr
#include <linux/icmp.h> // icmphdr
#include <linux/icmpv6.h> // icmp6hdr

struct tcpopts {
    unsigned int enabled : 1;

    unsigned int check_sport : 1;
    __u16 sport;

    unsigned int check_dport : 1;
    __u16 dport;

    // TCP flags.
    unsigned int check_urg : 1;
    unsigned int urg : 1;

    unsigned int check_ack : 1;
    unsigned int ack : 1;

    unsigned int check_rst : 1;
    unsigned int rst : 1;

    unsigned int check_psh : 1;
    unsigned int psh : 1;

    unsigned int check_syn : 1;
    unsigned int syn : 1;

    unsigned int check_fin : 1;
    unsigned int fin : 1;

    unsigned int check_ece : 1;
    unsigned int ece : 1;

    unsigned int check_cwr : 1;
    unsigned int cwr : 1;
};

struct udpopts
{
    unsigned int enabled : 1;

    unsigned int check_sport : 1;
    __u16 sport;

    unsigned int check_dport : 1;
    __u16 dport;
};

struct icmpopts
{
    unsigned int enabled : 1;

    unsigned int check_code : 1;
    __u8 code;

    unsigned int check_type : 1;
    __u8 type;
};

struct filter {
  /*ethhdr*/
//   unsigned char h_dest[ETH_ALEN];
//   unsigned char h_source[ETH_ALEN];
//   __u16 h_proto;
  /*iphdr*/
//   __u8 protocol;
  __be32 ip_saddr; // こいつらだけビッグエンディアン!
  __be32 ip_daddr;
  int check_tos : 1;
  __u8 tos;
  int check_min_ttl : 1;
  __u8 min_ttl;
  int check_max_ttl : 1;
  __u8 max_ttl;
  int check_min_len : 1;
  __u16 min_len; // 大小比較を行うため，エンディアンをホストに合わせる必要あり
  int check_max_len : 1;
  __u16 max_len; // 同上
  /*ipv6hdr*/
  // TODO
  /*tcphdr*/
  struct tcpopts tcpopts;
  /*udphdr*/
  struct udpopts udpopts;
  /*icmphdr*/
  struct icmpopts icmpopts;
};

struct filter filters[16] = {
    {
        .ip_saddr = 0xC9010A0A, // 10.10.1.201
        .ip_daddr = 0x6D000A0A, // 10.10.0.109
        .check_tos = 1,
        .tos = 0,
        .check_min_ttl = 1,
        .min_ttl = 40,
        .check_max_ttl = 1,
        .max_ttl = 80,
        .check_min_len = 1,
        .min_len = 30,
        .check_max_len = 1,
        .max_len = 50,
        .tcpopts = {
            .enabled = 0,
            .check_sport = 1,
            .sport = 80,
            .check_dport = 1,
            .dport = 8080,
            .check_urg = 0,
            .urg = 0,
            .check_ack = 1,
            .ack = 1,
            .check_rst = 0,
            .rst = 0,
            .check_psh = 0,
            .psh = 0,
            .check_syn = 1,
            .syn = 1,
            .check_fin = 0,
            .fin = 0,
            .check_ece = 0,
            .ece = 0,
            .check_cwr = 0,
            .cwr = 0,
        },
        .udpopts = {
            .enabled = 1,
            .check_sport = 1,
            .sport = 1234,
            .check_dport = 1,
            .dport = 320,
        },
        .icmpopts = {
            .enabled = 0,
            .check_code = 1,
            .code = 0,
            .check_type = 1,
            .type = 8,
        }
    },
    {
        .ip_saddr = 0xC9010A0A, // 10.10.1.201
        .ip_daddr = 0x6D000A0A, // 10.10.0.109
        .check_tos = 1,
        .tos = 0,
        .check_min_ttl = 1,
        .min_ttl = 40,
        .check_max_ttl = 1,
        .max_ttl = 80,
        .check_min_len = 1,
        .min_len = 30,
        .check_max_len = 1,
        .max_len = 50,
        .tcpopts = {
            .enabled = 0,
            .check_sport = 1,
            .sport = 80,
            .check_dport = 1,
            .dport = 8080,
            .check_urg = 0,
            .urg = 0,
            .check_ack = 1,
            .ack = 1,
            .check_rst = 0,
            .rst = 0,
            .check_psh = 0,
            .psh = 0,
            .check_syn = 1,
            .syn = 1,
            .check_fin = 0,
            .fin = 0,
            .check_ece = 0,
            .ece = 0,
            .check_cwr = 0,
            .cwr = 0,
        },
        .udpopts = {
            .enabled = 1,
            .check_sport = 1,
            .sport = 1234,
            .check_dport = 1,
            .dport = 320,
        },
        .icmpopts = {
            .enabled = 0,
            .check_code = 1,
            .code = 0,
            .check_type = 1,
            .type = 8,
        }
    },
    {
        .ip_saddr = 0xC9010A0A, // 10.10.1.201
        .ip_daddr = 0x6D000A0A, // 10.10.0.109
        .check_tos = 1,
        .tos = 0,
        .check_min_ttl = 1,
        .min_ttl = 40,
        .check_max_ttl = 1,
        .max_ttl = 80,
        .check_min_len = 1,
        .min_len = 30,
        .check_max_len = 1,
        .max_len = 50,
        .tcpopts = {
            .enabled = 0,
            .check_sport = 1,
            .sport = 80,
            .check_dport = 1,
            .dport = 8080,
            .check_urg = 0,
            .urg = 0,
            .check_ack = 1,
            .ack = 1,
            .check_rst = 0,
            .rst = 0,
            .check_psh = 0,
            .psh = 0,
            .check_syn = 1,
            .syn = 1,
            .check_fin = 0,
            .fin = 0,
            .check_ece = 0,
            .ece = 0,
            .check_cwr = 0,
            .cwr = 0,
        },
        .udpopts = {
            .enabled = 1,
            .check_sport = 1,
            .sport = 1234,
            .check_dport = 1,
            .dport = 320,
        },
        .icmpopts = {
            .enabled = 0,
            .check_code = 1,
            .code = 0,
            .check_type = 1,
            .type = 8,
        }
    },
    {
        .ip_saddr = 0xC9010A0A, // 10.10.1.201
        .ip_daddr = 0x6D000A0A, // 10.10.0.109
        .check_tos = 1,
        .tos = 0,
        .check_min_ttl = 1,
        .min_ttl = 40,
        .check_max_ttl = 1,
        .max_ttl = 80,
        .check_min_len = 1,
        .min_len = 30,
        .check_max_len = 1,
        .max_len = 50,
        .tcpopts = {
            .enabled = 0,
            .check_sport = 1,
            .sport = 80,
            .check_dport = 1,
            .dport = 8080,
            .check_urg = 0,
            .urg = 0,
            .check_ack = 1,
            .ack = 1,
            .check_rst = 0,
            .rst = 0,
            .check_psh = 0,
            .psh = 0,
            .check_syn = 1,
            .syn = 1,
            .check_fin = 0,
            .fin = 0,
            .check_ece = 0,
            .ece = 0,
            .check_cwr = 0,
            .cwr = 0,
        },
        .udpopts = {
            .enabled = 1,
            .check_sport = 1,
            .sport = 1234,
            .check_dport = 1,
            .dport = 320,
        },
        .icmpopts = {
            .enabled = 0,
            .check_code = 1,
            .code = 0,
            .check_type = 1,
            .type = 8,
        }
    },
    {
        .ip_saddr = 0xC9010A0A, // 10.10.1.201
        .ip_daddr = 0x6D000A0A, // 10.10.0.109
        .check_tos = 1,
        .tos = 0,
        .check_min_ttl = 1,
        .min_ttl = 40,
        .check_max_ttl = 1,
        .max_ttl = 80,
        .check_min_len = 1,
        .min_len = 30,
        .check_max_len = 1,
        .max_len = 50,
        .tcpopts = {
            .enabled = 0,
            .check_sport = 1,
            .sport = 80,
            .check_dport = 1,
            .dport = 8080,
            .check_urg = 0,
            .urg = 0,
            .check_ack = 1,
            .ack = 1,
            .check_rst = 0,
            .rst = 0,
            .check_psh = 0,
            .psh = 0,
            .check_syn = 1,
            .syn = 1,
            .check_fin = 0,
            .fin = 0,
            .check_ece = 0,
            .ece = 0,
            .check_cwr = 0,
            .cwr = 0,
        },
        .udpopts = {
            .enabled = 1,
            .check_sport = 1,
            .sport = 1234,
            .check_dport = 1,
            .dport = 320,
        },
        .icmpopts = {
            .enabled = 0,
            .check_code = 1,
            .code = 0,
            .check_type = 1,
            .type = 8,
        }
    },
    {
        .ip_saddr = 0xC9010A0A, // 10.10.1.201
        .ip_daddr = 0x6D000A0A, // 10.10.0.109
        .check_tos = 1,
        .tos = 0,
        .check_min_ttl = 1,
        .min_ttl = 40,
        .check_max_ttl = 1,
        .max_ttl = 80,
        .check_min_len = 1,
        .min_len = 30,
        .check_max_len = 1,
        .max_len = 50,
        .tcpopts = {
            .enabled = 0,
            .check_sport = 1,
            .sport = 80,
            .check_dport = 1,
            .dport = 8080,
            .check_urg = 0,
            .urg = 0,
            .check_ack = 1,
            .ack = 1,
            .check_rst = 0,
            .rst = 0,
            .check_psh = 0,
            .psh = 0,
            .check_syn = 1,
            .syn = 1,
            .check_fin = 0,
            .fin = 0,
            .check_ece = 0,
            .ece = 0,
            .check_cwr = 0,
            .cwr = 0,
        },
        .udpopts = {
            .enabled = 1,
            .check_sport = 1,
            .sport = 1234,
            .check_dport = 1,
            .dport = 320,
        },
        .icmpopts = {
            .enabled = 0,
            .check_code = 1,
            .code = 0,
            .check_type = 1,
            .type = 8,
        }
    },
    {
        .ip_saddr = 0xC9010A0A, // 10.10.1.201
        .ip_daddr = 0x6D000A0A, // 10.10.0.109
        .check_tos = 1,
        .tos = 0,
        .check_min_ttl = 1,
        .min_ttl = 40,
        .check_max_ttl = 1,
        .max_ttl = 80,
        .check_min_len = 1,
        .min_len = 30,
        .check_max_len = 1,
        .max_len = 50,
        .tcpopts = {
            .enabled = 0,
            .check_sport = 1,
            .sport = 80,
            .check_dport = 1,
            .dport = 8080,
            .check_urg = 0,
            .urg = 0,
            .check_ack = 1,
            .ack = 1,
            .check_rst = 0,
            .rst = 0,
            .check_psh = 0,
            .psh = 0,
            .check_syn = 1,
            .syn = 1,
            .check_fin = 0,
            .fin = 0,
            .check_ece = 0,
            .ece = 0,
            .check_cwr = 0,
            .cwr = 0,
        },
        .udpopts = {
            .enabled = 1,
            .check_sport = 1,
            .sport = 1234,
            .check_dport = 1,
            .dport = 320,
        },
        .icmpopts = {
            .enabled = 0,
            .check_code = 1,
            .code = 0,
            .check_type = 1,
            .type = 8,
        }
    },
    {
        .ip_saddr = 0xC9010A0A, // 10.10.1.201
        .ip_daddr = 0x6D000A0A, // 10.10.0.109
        .check_tos = 1,
        .tos = 0,
        .check_min_ttl = 1,
        .min_ttl = 40,
        .check_max_ttl = 1,
        .max_ttl = 80,
        .check_min_len = 1,
        .min_len = 30,
        .check_max_len = 1,
        .max_len = 50,
        .tcpopts = {
            .enabled = 0,
            .check_sport = 1,
            .sport = 80,
            .check_dport = 1,
            .dport = 8080,
            .check_urg = 0,
            .urg = 0,
            .check_ack = 1,
            .ack = 1,
            .check_rst = 0,
            .rst = 0,
            .check_psh = 0,
            .psh = 0,
            .check_syn = 1,
            .syn = 1,
            .check_fin = 0,
            .fin = 0,
            .check_ece = 0,
            .ece = 0,
            .check_cwr = 0,
            .cwr = 0,
        },
        .udpopts = {
            .enabled = 1,
            .check_sport = 1,
            .sport = 1234,
            .check_dport = 1,
            .dport = 320,
        },
        .icmpopts = {
            .enabled = 0,
            .check_code = 1,
            .code = 0,
            .check_type = 1,
            .type = 8,
        }
    },
    {
        .ip_saddr = 0xC9010A0A, // 10.10.1.201
        .ip_daddr = 0x6D000A0A, // 10.10.0.109
        .check_tos = 1,
        .tos = 0,
        .check_min_ttl = 1,
        .min_ttl = 40,
        .check_max_ttl = 1,
        .max_ttl = 80,
        .check_min_len = 1,
        .min_len = 30,
        .check_max_len = 1,
        .max_len = 50,
        .tcpopts = {
            .enabled = 0,
            .check_sport = 1,
            .sport = 80,
            .check_dport = 1,
            .dport = 8080,
            .check_urg = 0,
            .urg = 0,
            .check_ack = 1,
            .ack = 1,
            .check_rst = 0,
            .rst = 0,
            .check_psh = 0,
            .psh = 0,
            .check_syn = 1,
            .syn = 1,
            .check_fin = 0,
            .fin = 0,
            .check_ece = 0,
            .ece = 0,
            .check_cwr = 0,
            .cwr = 0,
        },
        .udpopts = {
            .enabled = 1,
            .check_sport = 1,
            .sport = 1234,
            .check_dport = 1,
            .dport = 320,
        },
        .icmpopts = {
            .enabled = 0,
            .check_code = 1,
            .code = 0,
            .check_type = 1,
            .type = 8,
        }
    },
    {
        .ip_saddr = 0xC9010A0A, // 10.10.1.201
        .ip_daddr = 0x6D000A0A, // 10.10.0.109
        .check_tos = 1,
        .tos = 0,
        .check_min_ttl = 1,
        .min_ttl = 40,
        .check_max_ttl = 1,
        .max_ttl = 80,
        .check_min_len = 1,
        .min_len = 30,
        .check_max_len = 1,
        .max_len = 50,
        .tcpopts = {
            .enabled = 0,
            .check_sport = 1,
            .sport = 80,
            .check_dport = 1,
            .dport = 8080,
            .check_urg = 0,
            .urg = 0,
            .check_ack = 1,
            .ack = 1,
            .check_rst = 0,
            .rst = 0,
            .check_psh = 0,
            .psh = 0,
            .check_syn = 1,
            .syn = 1,
            .check_fin = 0,
            .fin = 0,
            .check_ece = 0,
            .ece = 0,
            .check_cwr = 0,
            .cwr = 0,
        },
        .udpopts = {
            .enabled = 1,
            .check_sport = 1,
            .sport = 1234,
            .check_dport = 1,
            .dport = 320,
        },
        .icmpopts = {
            .enabled = 0,
            .check_code = 1,
            .code = 0,
            .check_type = 1,
            .type = 8,
        }
    },
    {
        .ip_saddr = 0xC9010A0A, // 10.10.1.201
        .ip_daddr = 0x6D000A0A, // 10.10.0.109
        .check_tos = 1,
        .tos = 0,
        .check_min_ttl = 1,
        .min_ttl = 40,
        .check_max_ttl = 1,
        .max_ttl = 80,
        .check_min_len = 1,
        .min_len = 30,
        .check_max_len = 1,
        .max_len = 50,
        .tcpopts = {
            .enabled = 0,
            .check_sport = 1,
            .sport = 80,
            .check_dport = 1,
            .dport = 8080,
            .check_urg = 0,
            .urg = 0,
            .check_ack = 1,
            .ack = 1,
            .check_rst = 0,
            .rst = 0,
            .check_psh = 0,
            .psh = 0,
            .check_syn = 1,
            .syn = 1,
            .check_fin = 0,
            .fin = 0,
            .check_ece = 0,
            .ece = 0,
            .check_cwr = 0,
            .cwr = 0,
        },
        .udpopts = {
            .enabled = 1,
            .check_sport = 1,
            .sport = 1234,
            .check_dport = 1,
            .dport = 320,
        },
        .icmpopts = {
            .enabled = 0,
            .check_code = 1,
            .code = 0,
            .check_type = 1,
            .type = 8,
        }
    },
    {
        .ip_saddr = 0xC9010A0A, // 10.10.1.201
        .ip_daddr = 0x6D000A0A, // 10.10.0.109
        .check_tos = 1,
        .tos = 0,
        .check_min_ttl = 1,
        .min_ttl = 40,
        .check_max_ttl = 1,
        .max_ttl = 80,
        .check_min_len = 1,
        .min_len = 30,
        .check_max_len = 1,
        .max_len = 50,
        .tcpopts = {
            .enabled = 0,
            .check_sport = 1,
            .sport = 80,
            .check_dport = 1,
            .dport = 8080,
            .check_urg = 0,
            .urg = 0,
            .check_ack = 1,
            .ack = 1,
            .check_rst = 0,
            .rst = 0,
            .check_psh = 0,
            .psh = 0,
            .check_syn = 1,
            .syn = 1,
            .check_fin = 0,
            .fin = 0,
            .check_ece = 0,
            .ece = 0,
            .check_cwr = 0,
            .cwr = 0,
        },
        .udpopts = {
            .enabled = 1,
            .check_sport = 1,
            .sport = 1234,
            .check_dport = 1,
            .dport = 320,
        },
        .icmpopts = {
            .enabled = 0,
            .check_code = 1,
            .code = 0,
            .check_type = 1,
            .type = 8,
        }
    },
    {
        .ip_saddr = 0xC9010A0A, // 10.10.1.201
        .ip_daddr = 0x6D000A0A, // 10.10.0.109
        .check_tos = 1,
        .tos = 0,
        .check_min_ttl = 1,
        .min_ttl = 40,
        .check_max_ttl = 1,
        .max_ttl = 80,
        .check_min_len = 1,
        .min_len = 30,
        .check_max_len = 1,
        .max_len = 50,
        .tcpopts = {
            .enabled = 0,
            .check_sport = 1,
            .sport = 80,
            .check_dport = 1,
            .dport = 8080,
            .check_urg = 0,
            .urg = 0,
            .check_ack = 1,
            .ack = 1,
            .check_rst = 0,
            .rst = 0,
            .check_psh = 0,
            .psh = 0,
            .check_syn = 1,
            .syn = 1,
            .check_fin = 0,
            .fin = 0,
            .check_ece = 0,
            .ece = 0,
            .check_cwr = 0,
            .cwr = 0,
        },
        .udpopts = {
            .enabled = 1,
            .check_sport = 1,
            .sport = 1234,
            .check_dport = 1,
            .dport = 320,
        },
        .icmpopts = {
            .enabled = 0,
            .check_code = 1,
            .code = 0,
            .check_type = 1,
            .type = 8,
        }
    },
    {
        .ip_saddr = 0xC9010A0A, // 10.10.1.201
        .ip_daddr = 0x6D000A0A, // 10.10.0.109
        .check_tos = 1,
        .tos = 0,
        .check_min_ttl = 1,
        .min_ttl = 40,
        .check_max_ttl = 1,
        .max_ttl = 80,
        .check_min_len = 1,
        .min_len = 30,
        .check_max_len = 1,
        .max_len = 50,
        .tcpopts = {
            .enabled = 0,
            .check_sport = 1,
            .sport = 80,
            .check_dport = 1,
            .dport = 8080,
            .check_urg = 0,
            .urg = 0,
            .check_ack = 1,
            .ack = 1,
            .check_rst = 0,
            .rst = 0,
            .check_psh = 0,
            .psh = 0,
            .check_syn = 1,
            .syn = 1,
            .check_fin = 0,
            .fin = 0,
            .check_ece = 0,
            .ece = 0,
            .check_cwr = 0,
            .cwr = 0,
        },
        .udpopts = {
            .enabled = 1,
            .check_sport = 1,
            .sport = 1234,
            .check_dport = 1,
            .dport = 320,
        },
        .icmpopts = {
            .enabled = 0,
            .check_code = 1,
            .code = 0,
            .check_type = 1,
            .type = 8,
        }
    },
    {
        .ip_saddr = 0xC9010A0A, // 10.10.1.201
        .ip_daddr = 0x6D000A0A, // 10.10.0.109
        .check_tos = 1,
        .tos = 0,
        .check_min_ttl = 1,
        .min_ttl = 40,
        .check_max_ttl = 1,
        .max_ttl = 80,
        .check_min_len = 1,
        .min_len = 30,
        .check_max_len = 1,
        .max_len = 50,
        .tcpopts = {
            .enabled = 0,
            .check_sport = 1,
            .sport = 80,
            .check_dport = 1,
            .dport = 8080,
            .check_urg = 0,
            .urg = 0,
            .check_ack = 1,
            .ack = 1,
            .check_rst = 0,
            .rst = 0,
            .check_psh = 0,
            .psh = 0,
            .check_syn = 1,
            .syn = 1,
            .check_fin = 0,
            .fin = 0,
            .check_ece = 0,
            .ece = 0,
            .check_cwr = 0,
            .cwr = 0,
        },
        .udpopts = {
            .enabled = 1,
            .check_sport = 1,
            .sport = 1234,
            .check_dport = 1,
            .dport = 320,
        },
        .icmpopts = {
            .enabled = 0,
            .check_code = 1,
            .code = 0,
            .check_type = 1,
            .type = 8,
        }
    },
    {
        .ip_saddr = 0xC9010A0A, // 10.10.1.201
        .ip_daddr = 0x6D000A0A, // 10.10.0.109
        .check_tos = 1,
        .tos = 0,
        .check_min_ttl = 1,
        .min_ttl = 40,
        .check_max_ttl = 1,
        .max_ttl = 80,
        .check_min_len = 1,
        .min_len = 30,
        .check_max_len = 1,
        .max_len = 50,
        .tcpopts = {
            .enabled = 0,
            .check_sport = 1,
            .sport = 80,
            .check_dport = 1,
            .dport = 8080,
            .check_urg = 0,
            .urg = 0,
            .check_ack = 1,
            .ack = 1,
            .check_rst = 0,
            .rst = 0,
            .check_psh = 0,
            .psh = 0,
            .check_syn = 1,
            .syn = 1,
            .check_fin = 0,
            .fin = 0,
            .check_ece = 0,
            .ece = 0,
            .check_cwr = 0,
            .cwr = 0,
        },
        .udpopts = {
            .enabled = 1,
            .check_sport = 1,
            .sport = 1234,
            .check_dport = 1,
            .dport = 319,
        },
        .icmpopts = {
            .enabled = 0,
            .check_code = 1,
            .code = 0,
            .check_type = 1,
            .type = 8,
        }
    },
};

const uint16_t UINT16_MAX = 0xffff;

enum {
  SLOWPATH_REASON = 1,
};

enum {
  DROP,      // drop packet
  SLOWPATH,  // send packet to user-space
  FORWARD,   // forward packet between ports
};

/*
 * BPF map of single element that saves the action to be applied in packets
 */
BPF_ARRAY(action_map, uint8_t, 1);

/*
 * BPF map where the ids of the ports are saved.  This module supports at most
 * two ports
 */
BPF_ARRAY(ports_map, uint16_t, 2);

/*
 * This function is called each time a packet arrives to the cube.
 * ctx contains the packet and md some additional metadata for the packet.
 * If the service is of type XDP_SKB/DRV CTXTYPE is equivalent to the struct
 * xdp_md
 * otherwise, if the service is of type TC, CTXTYPE is equivalent to the
 * __sk_buff struct
 * Please look at the polycube documentation for more details.
 */

static __always_inline void swap_src_dst_mac(void *data) {
  unsigned short *p = data;
  unsigned short dst[3];

  dst[0] = p[0];
  dst[1] = p[1];
  dst[2] = p[2];
  p[0] = p[3];
  p[1] = p[4];
  p[2] = p[5];
  p[3] = dst[0];
  p[4] = dst[1];
  p[5] = dst[2];
}

static int handle_rx(struct CTXTYPE *ctx, struct pkt_metadata *md) {
  pcn_log(ctx, LOG_DEBUG, "[INGRESS] Receiving packet from port %d", md->in_port);

  unsigned int zero = 0;
  unsigned int one = 1;

  // uint8_t *action = action_map.lookup(&zero);
  // if (!action) {
  //   return RX_DROP;
  // }
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;
  struct iphdr *iph = NULL;
  struct ipv6hdr *iph6 = NULL;
  struct tcphdr *tcph = NULL;
  struct udphdr *udph = NULL;
  struct icmphdr *icmph = NULL;
  struct icmp6hdr *icmp6h = NULL;
  struct filter filter;
  if ((void *)(eth + 1) > data_end)
    return XDP_PASS;
  if (eth->h_proto == bpf_htons(ETH_P_IP)) {
    iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
      return XDP_PASS;
    switch (iph->protocol) {
      case IPPROTO_TCP:
        tcph = (struct tcphdr *)(iph + 1);
        break;
      case IPPROTO_UDP:
        udph = (struct udphdr *)(iph + 1);
        break;
      case IPPROTO_ICMP:
        icmph = (struct icmphdr *)(iph + 1);
        break;
      case IPPROTO_ICMPV6:
        icmp6h = (struct icmp6hdr *)(iph + 1);
        break;
    }
  } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
    iph6 = (struct ipv6hdr *)(eth + 1);
    if ((void *)(iph6 + 1) > data_end)
      return XDP_PASS;
    switch (iph6->nexthdr) {
      case IPPROTO_TCP:
        tcph = (struct tcphdr *)(iph6 + 1);
        break;
      case IPPROTO_UDP:
        udph = (struct udphdr *)(iph6 + 1);
        break;
      case IPPROTO_ICMP:
        icmph = (struct icmphdr *)(iph6 + 1);
        break;
      case IPPROTO_ICMPV6:
        icmp6h = (struct icmp6hdr *)(iph6 + 1);
        break;
    }
  } else {
    return XDP_PASS;
  }

  for (int i = 0; i < 16; i++) {
    filter = filters[2];
    if (iph != NULL) {
      if (filter.ip_saddr && iph->saddr != filter.ip_saddr) //TODO エンディアン?
        continue;
      if (filter.ip_daddr && iph->daddr != filter.ip_daddr)
        continue;
      // TODO ALLOWSINGLEIPV4V6 への対応
      if (filter.check_tos && iph->tos != filter.tos)
        continue;
      if (filter.check_min_ttl && iph->ttl < filter.min_ttl)
        continue;
      if (filter.check_max_ttl && iph->ttl > filter.max_ttl)
        continue;
      if (filter.check_min_len && bpf_ntohs(iph->tot_len) < filter.min_len)
        continue;
      if (filter.check_max_len && bpf_ntohs(iph->tot_len) > filter.max_len)
        continue;
    } else if (iph6 != NULL) {
      ;
    }
    if (filter.tcpopts.enabled) {
      if ((void *)(tcph + 1) > data_end)
        return XDP_PASS;
      if (tcph == NULL) 
        continue;
      // if (filter.tcpopts.check_sport && bpf_htons(filter.tcpopts.sport) != tcph->source)
      //   continue;
      // if (filter.tcpopts.check_dport && bpf_htons(filter.tcpopts.dport) != tcph->dest)
      //   continue;
      // if (filter.tcpopts.check_urg && filter.tcpopts.urg != tcph->urg)
      //   continue;
      // if (filter.tcpopts.check_ack && filter.tcpopts.ack != tcph->ack)
      //   continue;
      // if (filter.tcpopts.check_rst && filter.tcpopts.rst != tcph->rst)
      //   continue;
      // if (filter.tcpopts.check_psh && filter.tcpopts.psh != tcph->psh)
      //   continue;
      // if (filter.tcpopts.check_syn && filter.tcpopts.syn != tcph->syn)
      //   continue;
      // if (filter.tcpopts.check_fin && filter.tcpopts.fin != tcph->fin)
      //   continue;
      // if (filter.tcpopts.check_ece && filter.tcpopts.ece != tcph->ece)
      //   continue;
      // if (filter.tcpopts.check_cwr && filter.tcpopts.cwr != tcph->cwr)
      //   continue;
    } else if (filter.udpopts.enabled) {
      if (udph == NULL)
        continue;
      if ((void *)(udph + 1) > data_end)
        return XDP_PASS;
      if (filter.udpopts.check_sport && bpf_htons(filter.udpopts.sport) != udph->source)
        continue;
      if (filter.udpopts.check_dport && bpf_htons(filter.udpopts.dport) != udph->dest)
        continue;
    } else if (filter.icmpopts.enabled) {
      if (icmph != NULL) {
        continue;
        // if (filter.icmpopts.check_code && filter.icmpopts.code != icmph->code)
        //   continue;
        // if (filter.icmpopts.check_type && filter.icmpopts.type != icmph->type)
        //   continue;
      } else if (icmp6h != NULL) {
        continue;
        // if (filter.icmpopts.check_code && filter.icmpopts.code != icmp6h->icmp6_code)
        //   continue;
        // if (filter.icmpopts.check_type && filter.icmpopts.type != icmp6h->icmp6_type)
        //   continue;
      } else {
        continue;
      }
    } else {
      continue;
    }
    return XDP_DROP;
  }
  swap_src_dst_mac(data);
  pcn_log(ctx, LOG_DEBUG, "Sending packet to slow path");
  pcn_pkt_controller(ctx, md, SLOWPATH_REASON);
  return RX_DROP;

  // what action should be performed in the packet?
  // switch (*action) {
  // case DROP:
  //   pcn_log(ctx, LOG_DEBUG, "Dropping packet");
  //   return RX_DROP;
  // case SLOWPATH:
  //   pcn_log(ctx, LOG_DEBUG, "Sending packet to slow path");
  //   pcn_pkt_controller(ctx, md, SLOWPATH_REASON);
  //   return RX_DROP;
  // case FORWARD: ;
  //   // Get ports ids
  //   uint16_t *p1 = ports_map.lookup(&zero);
  //   if (!p1 || *p1 == UINT16_MAX) {
  //     return RX_DROP;
  //   }

  //   uint16_t *p2 = ports_map.lookup(&one);
  //   if (!p2 || *p2 == UINT16_MAX) {
  //     return RX_DROP;
  //   }

  //   pcn_log(ctx, LOG_DEBUG, "Forwarding packet");

  //   uint16_t outport = md->in_port == *p1 ? *p2 : *p1;
  //   return pcn_pkt_redirect(ctx, md, outport);
  // default:
  //   // if control plane is well implemented this will never happen
  //   pcn_log(ctx, LOG_ERR, "bad action %d", *action);
  //   return RX_DROP;
  // }
}
