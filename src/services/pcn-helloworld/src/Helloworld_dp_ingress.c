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
#include <asm/byteorder.h>
#include <linux/types.h>
// #include <linux/ip.h> // iphdr
// #include <linux/ipv6.h> //ipv6hdr
// #include <linux/udp.h> // udphdr
// #include <linux/tcp.h> // tcphdr
// #include <linux/icmp.h> // icmphdr
// #include <linux/icmpv6.h> // icmp6hdr
// struct iphdr {
// #if defined(__LITTLE_ENDIAN_BITFIELD)
//         __u8    ihl:4,
//                 version:4;
// #elif defined (__BIG_ENDIAN_BITFIELD)
//         __u8    version:4,
//                 ihl:4;
// #else
// #error  "Please fix <asm/byteorder.h>"
// #endif
//         __u8    tos;
//         __be16  tot_len;
//         __be16  id;
//         __be16  frag_off;
//         __u8    ttl;
//         __u8    protocol;
//         __sum16 check;
//         __be32  saddr;
//         __be32  daddr;
//         /*The options start here. */
// };
enum
  {
    IPPROTO_IP = 0,        /* Dummy protocol for TCP.  */
#define IPPROTO_IP              IPPROTO_IP
    IPPROTO_ICMP = 1,      /* Internet Control Message Protocol.  */
#define IPPROTO_ICMP            IPPROTO_ICMP
    IPPROTO_IGMP = 2,      /* Internet Group Management Protocol. */
#define IPPROTO_IGMP            IPPROTO_IGMP
    IPPROTO_IPIP = 4,      /* IPIP tunnels (older KA9Q tunnels use 94).  */
#define IPPROTO_IPIP            IPPROTO_IPIP
    IPPROTO_TCP = 6,       /* Transmission Control Protocol.  */
#define IPPROTO_TCP             IPPROTO_TCP
    IPPROTO_EGP = 8,       /* Exterior Gateway Protocol.  */
#define IPPROTO_EGP             IPPROTO_EGP
    IPPROTO_PUP = 12,      /* PUP protocol.  */
#define IPPROTO_PUP             IPPROTO_PUP
    IPPROTO_UDP = 17,      /* User Datagram Protocol.  */
#define IPPROTO_UDP             IPPROTO_UDP
    IPPROTO_IDP = 22,      /* XNS IDP protocol.  */
#define IPPROTO_IDP             IPPROTO_IDP
    IPPROTO_TP = 29,       /* SO Transport Protocol Class 4.  */
#define IPPROTO_TP              IPPROTO_TP
    IPPROTO_DCCP = 33,     /* Datagram Congestion Control Protocol.  */
#define IPPROTO_DCCP            IPPROTO_DCCP
    IPPROTO_IPV6 = 41,     /* IPv6 header.  */
#define IPPROTO_IPV6            IPPROTO_IPV6
    IPPROTO_RSVP = 46,     /* Reservation Protocol.  */
#define IPPROTO_RSVP            IPPROTO_RSVP
    IPPROTO_GRE = 47,      /* General Routing Encapsulation.  */
#define IPPROTO_GRE             IPPROTO_GRE
    IPPROTO_ESP = 50,      /* encapsulating security payload.  */
#define IPPROTO_ESP             IPPROTO_ESP
    IPPROTO_AH = 51,       /* authentication header.  */
#define IPPROTO_AH              IPPROTO_AH
    IPPROTO_MTP = 92,      /* Multicast Transport Protocol.  */
#define IPPROTO_MTP             IPPROTO_MTP
    IPPROTO_BEETPH = 94,   /* IP option pseudo header for BEET.  */
#define IPPROTO_BEETPH          IPPROTO_BEETPH
    IPPROTO_ENCAP = 98,    /* Encapsulation Header.  */
#define IPPROTO_ENCAP           IPPROTO_ENCAP
    IPPROTO_PIM = 103,     /* Protocol Independent Multicast.  */
#define IPPROTO_PIM             IPPROTO_PIM
    IPPROTO_COMP = 108,    /* Compression Header Protocol.  */
#define IPPROTO_COMP            IPPROTO_COMP
    IPPROTO_SCTP = 132,    /* Stream Control Transmission Protocol.  */
#define IPPROTO_SCTP            IPPROTO_SCTP
    IPPROTO_UDPLITE = 136, /* UDP-Lite protocol.  */
#define IPPROTO_UDPLITE         IPPROTO_UDPLITE
    IPPROTO_MPLS = 137,    /* MPLS in IP.  */
#define IPPROTO_MPLS            IPPROTO_MPLS
    IPPROTO_RAW = 255,     /* Raw IP packets.  */
#define IPPROTO_RAW             IPPROTO_RAW
    IPPROTO_MAX
  };
enum
  {
    IPPROTO_HOPOPTS = 0,   /* IPv6 Hop-by-Hop options.  */
#define IPPROTO_HOPOPTS         IPPROTO_HOPOPTS
    IPPROTO_ROUTING = 43,  /* IPv6 routing header.  */
#define IPPROTO_ROUTING         IPPROTO_ROUTING
    IPPROTO_FRAGMENT = 44, /* IPv6 fragmentation header.  */
#define IPPROTO_FRAGMENT        IPPROTO_FRAGMENT
    IPPROTO_ICMPV6 = 58,   /* ICMPv6.  */
#define IPPROTO_ICMPV6          IPPROTO_ICMPV6
    IPPROTO_NONE = 59,     /* IPv6 no next header.  */
#define IPPROTO_NONE            IPPROTO_NONE
    IPPROTO_DSTOPTS = 60,  /* IPv6 destination options.  */
#define IPPROTO_DSTOPTS         IPPROTO_DSTOPTS
    IPPROTO_MH = 135       /* IPv6 mobility header.  */
#define IPPROTO_MH              IPPROTO_MH
  };
struct in6_addr {
	union {
		__u8		u6_addr8[16];
#if __UAPI_DEF_IN6_ADDR_ALT
		__be16		u6_addr16[8];
		__be32		u6_addr32[4];
#endif
	} in6_u;
#define s6_addr			in6_u.u6_addr8
#if __UAPI_DEF_IN6_ADDR_ALT
#define s6_addr16		in6_u.u6_addr16
#define s6_addr32		in6_u.u6_addr32
#endif
};
struct ipv6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
        __u8                    priority:4,
                                version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
        __u8                    version:4,
                                priority:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
        __u8                    flow_lbl[3];

        __be16                  payload_len;
        __u8                    nexthdr;
        __u8                    hop_limit;

        struct  in6_addr        saddr;
        struct  in6_addr        daddr;
};
struct tcphdr {
        __be16  source;
        __be16  dest;
        __be32  seq;
        __be32  ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
        __u16   res1:4,
                doff:4,
                fin:1,
                syn:1,
                rst:1,
                psh:1,
                ack:1,
                urg:1,
                ece:1,
                cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
        __u16   doff:4,
                res1:4,
                cwr:1,
                ece:1,
                urg:1,
                ack:1,
                psh:1,
                rst:1,
                syn:1,
                fin:1;
#else
#error  "Adjust your <asm/byteorder.h> defines"
#endif
        __be16  window;
        __sum16 check;
        __be16  urg_ptr;
};
struct udphdr {
        __be16  source;
        __be16  dest;
        __be16  len;
        __sum16 check;
};

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

static struct filter filter = {
        .ip_saddr = 0xC9010A0A, // 10.10.1.201
        .ip_daddr = 0x81000A0A, // 10.10.0.128
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
//   if (eth->h_proto == bpf_htons(ETH_P_IP)) {
//     iph = (struct iphdr *)(eth + 1);
//     if ((void *)(iph + 1) > data_end)
//       return XDP_PASS;
//     switch (iph->protocol) {
//       case IPPROTO_TCP:
//         tcph = (struct tcphdr *)(iph + 1);
//         break;
//       case IPPROTO_UDP:
//         udph = (struct udphdr *)(iph + 1);
//         if ((void *)(udph + 1) > data_end)
//           return XDP_PASS;
//         break;
//       case IPPROTO_ICMP:
//         icmph = (struct icmphdr *)(iph + 1);
//         break;
//       case IPPROTO_ICMPV6:
//         icmp6h = (struct icmp6hdr *)(iph + 1);
//         break;
//     }
//   } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
//     iph6 = (struct ipv6hdr *)(eth + 1);
//     if ((void *)(iph6 + 1) > data_end)
//       return XDP_PASS;
//     switch (iph6->nexthdr) {
//       case IPPROTO_TCP:
//         tcph = (struct tcphdr *)(iph6 + 1);
//         break;
//       case IPPROTO_UDP:
//         udph = (struct udphdr *)(iph6 + 1);
//         break;
//       case IPPROTO_ICMP:
//         icmph = (struct icmphdr *)(iph6 + 1);
//         break;
//       case IPPROTO_ICMPV6:
//         icmp6h = (struct icmp6hdr *)(iph6 + 1);
//         break;
//     }
//   } else {
//     return XDP_PASS;
//   }

//   for (int i = 0; i < 32; i++) {
//     if (iph != NULL) {
//       if (filter.ip_saddr && iph->saddr != filter.ip_saddr) //TODO エンディアン?
//         continue;
//       if (filter.ip_daddr && iph->daddr != filter.ip_daddr)
//         continue;
//       // TODO ALLOWSINGLEIPV4V6 への対応
//       // if (filter.check_tos && iph->tos != filter.tos)
//       //   continue;
//       // if (filter.check_min_ttl && iph->ttl < filter.min_ttl)
//       //   continue;
//       // if (filter.check_max_ttl && iph->ttl > filter.max_ttl)
//       //   continue;
//       // if (filter.check_min_len && bpf_ntohs(iph->tot_len) < filter.min_len)
//       //   continue;
//       // if (filter.check_max_len && bpf_ntohs(iph->tot_len) > filter.max_len)
//       //   continue;
//     } else if (iph6 != NULL) {
//       continue;
//     }
//     if (filter.tcpopts.enabled) {
//       continue;
//     } else if (filter.udpopts.enabled) {
//       if (udph == NULL)
//         continue;
//       if (filter.udpopts.check_sport && bpf_htons(filter.udpopts.sport) != udph->source)
//         continue;
//       if (filter.udpopts.check_dport && bpf_htons(filter.udpopts.dport) != udph->dest)
//         continue;
//     } else if (filter.icmpopts.enabled) {
//       if (icmph != NULL) {
//         continue;
//       } else if (icmp6h != NULL) {
//         continue;
//       } else {
//         continue;
//       }
//     } else {
//       continue;
//     }
//   }
//   swap_src_dst_mac(data);
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
