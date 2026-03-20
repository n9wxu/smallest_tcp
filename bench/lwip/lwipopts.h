/**
 * Minimal lwipopts.h for fair size comparison.
 * UDP only — no TCP, no DHCP, no DNS, no IGMP, no PPP.
 * Matches smallest_tcp feature set: ETH + ARP + IPv4 + ICMP + UDP.
 */

#ifndef LWIPOPTS_H
#define LWIPOPTS_H

/* ── Minimal system ───────────────────────────────────────────────── */
#define NO_SYS 1 /* No OS, bare-metal */
#define LWIP_NOASSERT 1
#define LWIP_STATS 0
#define LWIP_DEBUG 0
#define MEM_LIBC_MALLOC 0
#define MEMP_MEM_MALLOC 0
#define MEM_ALIGNMENT 4

/* ── Memory pools (tuned small) ───────────────────────────────────── */
#define MEM_SIZE 1024
#define MEMP_NUM_PBUF 4
#define MEMP_NUM_UDP_PCB 1
#define MEMP_NUM_TCP_PCB 0
#define MEMP_NUM_TCP_PCB_LISTEN 0
#define MEMP_NUM_TCP_SEG 0
#define MEMP_NUM_REASSDATA 0
#define MEMP_NUM_ARP_QUEUE 2
#define PBUF_POOL_SIZE 4
#define PBUF_POOL_BUFSIZE 300

/* ── Protocols ────────────────────────────────────────────────────── */
#define LWIP_ARP 1
#define LWIP_IPV4 1
#define LWIP_ICMP 1
#define LWIP_UDP 1
#define LWIP_TCP 0 /* disabled for fair comparison */
#define LWIP_DHCP 0
#define LWIP_DNS 0
#define LWIP_IGMP 0
#define LWIP_IPV6 0
#define LWIP_RAW 0
#define LWIP_AUTOIP 0
#define LWIP_SNMP 0
#define LWIP_PPP 0
#define LWIP_NETIF_API 0
#define LWIP_SOCKET 0
#define LWIP_NETCONN 0

/* ── IP options ───────────────────────────────────────────────────── */
#define IP_REASSEMBLY 0
#define IP_FRAG 0
#define IP_OPTIONS_ALLOWED 0

/* ── Checksum ─────────────────────────────────────────────────────── */
#define CHECKSUM_GEN_IP 1
#define CHECKSUM_GEN_UDP 1
#define CHECKSUM_GEN_ICMP 1
#define CHECKSUM_CHECK_IP 1
#define CHECKSUM_CHECK_UDP 1

/* ── ARP ──────────────────────────────────────────────────────────── */
#define ARP_TABLE_SIZE 4
#define ARP_QUEUEING 0

/* ── Ethernet ─────────────────────────────────────────────────────── */
#define ETH_PAD_SIZE 0
#define LWIP_ETHERNET 1

#endif /* LWIPOPTS_H */
