# DHCPv4 Design

**Protocol:** Dynamic Host Configuration Protocol v4  
**Files:** `include/dhcpv4_client.h`, `src/dhcpv4_client.c`,
           `include/dhcpv4_server.h`, `src/dhcpv4_server.c`  
**Last updated:** 2026-03-21

---

## 1. Overview and Split Design

DHCPv4 is implemented as **two fully independent compilation units** — a client
and a minimal stateless server.  There is no shared header; an application links
only what it needs.

| Use case | What to link |
|---|---|
| MCU on an Ethernet LAN — gets IP from router | `dhcpv4_client.c` only |
| USB/CDC-ECM device — assigns IP to the PC peer | `dhcpv4_server.c` only |
| Two-interface bridge / router | Out of scope (single `net_t` / single MAC) |

Both units integrate with the existing UDP port-dispatch table.  The application
registers the DHCP port handler(s) in its `udp_port_table_t` just like any other
UDP service.

---

## 2. DHCPv4 Client

### 2.1 State Machine

```
INIT  ──DISCOVER──►  SELECTING  ──REQUEST──►  REQUESTING
                                                   │
                                             ACK ◄─┘   NAK → INIT
                                               │
                                            BOUND
                                          /         \
                               T1 expires             T2 expires
                                  │                       │
                               RENEWING             REBINDING
                                  │                       │
                             ACK→BOUND               ACK→BOUND
                             NAK→INIT                NAK→INIT
                             Expire→INIT             Expire→INIT
```

Timers (T1, T2, lease expiry) are driven by `dhcpv4_client_tick(ms)`, which the
application calls from its main loop alongside `tcp_tick` and ARP timers.

### 2.2 Client State Structure

```c
typedef struct {
    uint8_t   state;          /* DHCPV4_CLI_INIT … DHCPV4_CLI_REBINDING */
    uint32_t  xid;            /* current transaction ID (random)          */
    uint32_t  offered_ip;     /* IP offered by server                     */
    uint32_t  server_ip;      /* Server Identifier option (54)            */
    uint32_t  lease_time;     /* IP Address Lease Time option (51), secs  */
    uint32_t  t1;             /* Renewal Time (option 58, or 0.5×lease)   */
    uint32_t  t2;             /* Rebinding Time (option 59, or 0.875×lease) */
    uint32_t  timer_ms;       /* countdown to next action (ms)            */
    uint8_t   retries;        /* retransmit counter                       */

    const dhcpv4_opt_table_t *opt_table;  /* application-registered handlers */
    dhcpv4_event_fn_t         on_event;
    void                     *evt_ctx;
} dhcpv4_client_t;
```

All fields are zero-initialised via `dhcpv4_client_init()`.  The application
owns the struct (stack, static, or wherever it fits).

### 2.3 Client API

```c
/* Initialise — must be called before start.
   opts may be NULL if no option handlers are needed. */
void dhcpv4_client_init(dhcpv4_client_t *c,
                        dhcpv4_event_fn_t on_event, void *evt_ctx,
                        const dhcpv4_opt_table_t *opts);

/* Begin discovery — sends DHCPDISCOVER, starts retransmit timer.
   net->ip must be 0.0.0.0 (or will be overwritten on BOUND). */
void dhcpv4_client_start(net_t *net, dhcpv4_client_t *c);

/* Drive timers — call with elapsed ms from main loop. */
void dhcpv4_client_tick(net_t *net, dhcpv4_client_t *c, uint32_t ms);

/* Feed incoming UDP payload (port 68) to the client.
   Typically called from the application's UDP port-68 handler. */
void dhcpv4_client_input(net_t *net, dhcpv4_client_t *c,
                         uint32_t src_ip,
                         const uint8_t *data, uint16_t len);

/* Voluntarily release the lease (sends DHCPRELEASE, clears net->ip). */
void dhcpv4_client_release(net_t *net, dhcpv4_client_t *c);
```

### 2.4 Option Handler Callback API

```c
/**
 * Called by the DHCP client for each option found in DHCPACK / DHCPOFFER.
 *
 * The raw TLV value bytes are passed directly — the handler is responsible
 * for interpreting and transforming them into whatever the application needs.
 *
 *   option  — DHCP option code (e.g. 3=Router, 6=DNS, 42=NTP, 66=TFTP name)
 *   data    — pointer to value bytes (NOT including the type or length byte)
 *   len     — number of value bytes
 *   ctx     — the application context pointer from the registration entry
 *
 * The handler is invoked at most once per DHCPACK (including renewals).
 * If the option is absent from the server's reply, the handler is never called;
 * the application should initialise its target variables to a sensible default
 * before starting DHCP.
 */
typedef void (*dhcpv4_opt_handler_t)(uint8_t option,
                                     const uint8_t *data, uint8_t len,
                                     void *ctx);

typedef struct {
    uint8_t               option;   /* DHCP option code              */
    dhcpv4_opt_handler_t  handler;  /* application callback          */
    void                 *ctx;      /* passed through to handler      */
} dhcpv4_opt_entry_t;

typedef struct {
    const dhcpv4_opt_entry_t *entries;
    uint8_t                   count;
} dhcpv4_opt_table_t;
```

#### Example — TFTP server IP + NTP server list

```c
static uint32_t g_tftp_server = 0;          /* defaults: none */
static uint32_t g_ntp_servers[2] = {0, 0};
static uint8_t  g_ntp_count = 0;

static void on_tftp(uint8_t opt, const uint8_t *d, uint8_t len, void *ctx) {
    /* Option 150 value: one 4-byte IP address */
    if (len >= 4)
        g_tftp_server = net_rd32(d);   /* converts big-endian → host order */
}

static void on_ntp(uint8_t opt, const uint8_t *d, uint8_t len, void *ctx) {
    /* Option 42 value: list of 4-byte IP addresses */
    g_ntp_count = 0;
    for (uint8_t i = 0; i + 4 <= len && g_ntp_count < 2; i += 4)
        g_ntp_servers[g_ntp_count++] = net_rd32(d + i);
}

static const dhcpv4_opt_entry_t app_opts[] = {
    { 150, on_tftp, NULL },   /* TFTP server IP  (RFC 5859) */
    {  42, on_ntp,  NULL },   /* NTP server list            */
};
static const dhcpv4_opt_table_t opt_table = { app_opts, 2 };

/* Initialise: */
dhcpv4_client_init(&dhcp, on_dhcp_event, NULL, &opt_table);
```

After `DHCPV4_EVT_BOUND`, `g_tftp_server` is non-zero only if the server
included option 150.  If absent, it stays 0 (the default the app set before
calling `dhcpv4_client_start`).

### 2.5 Auto-build of Parameter Request List (Option 55)

When sending DHCPDISCOVER and DHCPREQUEST, the client automatically builds
option 55 (Parameter Request List) by combining:

1. **Mandatory built-ins:** subnet mask (1), router (3), IP address lease time (51)
2. **Application-registered codes:** every `option` field from `opt_table->entries`

This means the application expresses what it wants *purely by registering handlers*
— no separate "request list" configuration needed.

---

## 3. DHCPv4 Server

### 3.1 Design Rationale

The server is **stateless and single-client**.  It always offers the same
pre-configured IP regardless of which MAC sent the DISCOVER.  This is the
correct model for a USB/CDC-ECM device where exactly one peer will ever connect.
There is no lease table, no lease expiry, and no ARP conflict detection.

### 3.2 Server Configuration

```c
typedef struct {
    uint32_t server_ip;      /* our IP (= the DHCP server's address)      */
    uint32_t offered_ip;     /* IP to offer and assign to the client       */
    uint32_t subnet_mask;    /* option 1                                   */
    uint32_t gateway;        /* option 3  — 0 = not included               */
    uint32_t dns;            /* option 6  — 0 = not included               */
    uint32_t lease_time_s;   /* option 51 — 0 = infinite (0xFFFFFFFF sent) */
} dhcpv4_server_cfg_t;
```

The configuration is owned by the application (const, in flash on MCUs).

### 3.3 Server State Structure

```c
typedef struct {
    const dhcpv4_server_cfg_t *cfg;
    dhcpv4_event_fn_t          on_event;
    void                      *evt_ctx;
} dhcpv4_server_t;
```

No dynamic state — `dhcpv4_server_input()` is pure stimulus/response.

### 3.4 Server API

```c
/* Initialise. cfg must remain valid for the lifetime of the server. */
void dhcpv4_server_init(dhcpv4_server_t *s,
                        const dhcpv4_server_cfg_t *cfg,
                        dhcpv4_event_fn_t on_event, void *evt_ctx);

/* Feed incoming UDP payload (port 67) to the server.
   Typically called from the application's UDP port-67 handler.
   src_mac is used to address the OFFER/ACK unicast/broadcast reply. */
void dhcpv4_server_input(net_t *net, dhcpv4_server_t *s,
                         uint32_t src_ip, const uint8_t *src_mac,
                         const uint8_t *data, uint16_t len);
```

### 3.5 Server Message Handling

| Incoming | Condition | Response |
|---|---|---|
| DHCPDISCOVER | always | DHCPOFFER with `cfg->offered_ip` |
| DHCPREQUEST | `Requested IP == offered_ip` | DHCPACK |
| DHCPREQUEST | `Requested IP != offered_ip` | DHCPNAK |
| DHCPRELEASE | always | ignore (no lease table) |
| DHCPINFORM | always | DHCPACK with options, yiaddr = 0 |
| anything else | — | ignore |

The server always broadcasts replies (flags bit 0 = 1 in OFFER/ACK) unless
the request came from a known unicast address with `ciaddr` set, in which case
it unicasts.

### 3.6 Application Wiring (UDP Port Table)

```c
/* Port-67 handler for the server */
static void dhcp_server_udp(net_t *net, uint32_t src_ip, uint16_t src_port,
                             const uint8_t *src_mac,
                             const uint8_t *data, uint16_t len) {
    dhcpv4_server_input(net, &srv, src_ip, src_mac, data, len);
}

/* Port-68 handler for the client */
static void dhcp_client_udp(net_t *net, uint32_t src_ip, uint16_t src_port,
                             const uint8_t *src_mac,
                             const uint8_t *data, uint16_t len) {
    dhcpv4_client_input(net, &cli, src_ip, data, len);
}
```

---

## 4. Buffer Size Constraints

Both client and server require the application's `net_t` tx/rx buffers to be
at least 576 bytes (RFC 2131 §2 minimum DHCP message size + 34 bytes ETH+IP+UDP
overhead = 610 bytes minimum frame buffer).

`dhcpv4_client_init()` and `dhcpv4_server_init()` validate the buffer size at
runtime and return `NET_ERR_BUFFER` if the buffer is too small.

---

## 5. Integration with the Timer Model

The client needs `dhcpv4_client_tick(net, c, elapsed_ms)` called from the same
main loop that drives `tcp_tick` and ARP timers.  The server has no timers.

```c
/* typical main loop: */
while (1) {
    net_poll(&net);                                  /* rx + dispatch         */
    uint32_t dt = elapsed_ms_since_last_tick();
    tcp_tick(&net, &conn, dt);
    dhcpv4_client_tick(&net, &dhcp, dt);             /* client only           */
}
```

---

## 6. Events and Application Lifecycle

When `DHCPV4_EVT_BOUND` fires:
1. `net->ip` has been set to the new IP address.
2. The gateway has been configured (if option 3 was present).
3. All option handlers in `opt_table` have been called for options present in
   the DHCPACK.  Handlers for absent options were not called.
4. The application may now initiate TCP connections, ARP resolution, TFTP, etc.

When `DHCPV4_EVT_EXPIRED` fires:
1. `net->ip` is cleared to 0.0.0.0.
2. All TCP connections should be torn down by the application.
3. The client automatically re-enters INIT and starts a new DISCOVER cycle.

---

## 7. Zero-Allocation Guarantee

Neither `dhcpv4_client.c` nor `dhcpv4_server.c` calls `malloc`, `calloc`, or
`realloc`.  All state is in application-owned structs.  The DHCP message is
built directly in `net->tx_buf` (the application's transmit buffer), consistent
with the zero-copy architecture used throughout the stack.
