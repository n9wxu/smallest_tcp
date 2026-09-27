/**
 * @file tls.c
 * @brief TLS 1.3 (RFC 8446) connections: records in and out, handshake
 *        message framing, alerts, KeyUpdate and the API.  The handshake
 *        of each role is in tls_server.c and tls_client.c.
 *
 * No division: this builds for Cortex-M0.
 */

#include "tls_internal.h"

#define NO_REC 0xFFFFu
#define BUF_MIN 256u
#define BUF_MAX 0xFFFEu
#define ALERT_WARNING 1
#define ALERT_FATAL 2

/* SHA-256("HelloRetryRequest") */
const uint8_t tls_hrr_random[TLS_RANDOM_LEN] = {
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c,
    0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb,
    0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};

static const uint8_t cv_server_context[] = "TLS 1.3, server CertificateVerify";

void tls_notify(tls_conn_t *t, uint8_t events) {
  if (t->on_event)
    t->on_event(t, events);
}

static void wipe_keys(tls_conn_t *t) {
  tls_wipe(t->secret, sizeof(t->secret));
  tls_wipe(t->rsec, sizeof(t->rsec));
  tls_wipe(t->wsec, sizeof(t->wsec));
  tls_wipe(&t->rkeys, sizeof(t->rkeys));
  tls_wipe(&t->wkeys, sizeof(t->wkeys));
}

/* ── Shared by both roles ── */

/* Extension types seen so far (below 64), to refuse duplicates */
static int already_seen(uint32_t seen[2], uint16_t type) {
  uint32_t bit;
  if (type >= 64)
    return 0;
  bit = 1ul << (type & 31u);
  if (seen[type >> 5] & bit)
    return 1;
  seen[type >> 5] |= bit;
  return 0;
}

int tls_next_extension(rd_t *exts, uint32_t seen[2], uint16_t *type,
                       rd_t *data) {
  *type = (uint16_t)rd_uint(exts, 2);
  *data = rd_vec(exts, 2);
  if (exts->bad)
    return TLS_ALERT_DECODE_ERROR;
  if (already_seen(seen, *type))
    return TLS_ALERT_ILLEGAL_PARAMETER;
  return 0;
}

uint8_t tls_groups(const tls_config_t *cfg) {
  return cfg->groups ? cfg->groups : TLS_GROUPS_X25519 | TLS_GROUPS_SECP256R1;
}

int tls_group_allowed(const tls_config_t *cfg, uint32_t group) {
  uint8_t mask = tls_groups(cfg);
  return (group == TLS_GROUP_X25519 && (mask & TLS_GROUPS_X25519)) ||
         (group == TLS_GROUP_SECP256R1 && (mask & TLS_GROUPS_SECP256R1));
}

void tls_cert_verify_content(const tls_conn_t *t,
                             uint8_t out[TLS_CV_CONTENT_LEN]) {
  memset(out, 0x20, 64);
  memcpy(out + 64, cv_server_context, sizeof(cv_server_context)); /* + 0 */
  t->cfg->crypto->hash_peek(&t->transcript,
                            out + 64 + sizeof(cv_server_context));
}

/* ── Building records ── */

void tls_tx_compact(tls_conn_t *t) {
  if (!t->tx_sent)
    return;
  memmove(t->tx, t->tx + t->tx_sent, (size_t)(t->tx_len - t->tx_sent));
  t->tx_len = (uint16_t)(t->tx_len - t->tx_sent);
  t->tx_sent = 0;
}

/* The most content a record of ours may carry */
static size_t fragment_limit(const tls_conn_t *t) {
  return t->max_frag ? t->max_frag : TLS_MAX_PLAINTEXT;
}

/* Bytes a record of ours adds to its content */
static size_t record_overhead(const tls_conn_t *t) {
  return TLS_RECORD_HDR + ((t->flags & F_WPROT) ? 1u + TLS_AEAD_TAG_LEN : 0u);
}

static void seal_record(tls_conn_t *t, uint8_t *rec, size_t len) {
  if (t->flags & F_WPROT) {
    tls_record_seal(t->cfg->crypto, &t->wkeys, t->rec_type, rec, len);
  } else {
    rec[0] = t->rec_type;
    net_write16be(rec + 1, TLS_LEGACY_VERSION);
    net_write16be(rec + 3, (uint16_t)len);
  }
}

/* A message longer than the fragment limit leaves as several records:
 * the pieces are spread out, last first, to their record's place
 * (tls_rec_room() reserved the room) */
void tls_rec_close(tls_conn_t *t) {
  size_t limit = fragment_limit(t), stride = limit + record_overhead(t);
  size_t len, piece, off, n = 1, i;
  if (t->rec_start == NO_REC)
    return;
  len = (size_t)(t->tx_len - t->rec_start - TLS_RECORD_HDR);
  for (off = limit; off < len; off += limit)
    n++;
  for (i = n - 1; i > 0; i--) {
    off = i * limit;
    piece = len - off < limit ? len - off : limit;
    memmove(t->tx + t->rec_start + i * stride + TLS_RECORD_HDR,
            t->tx + t->rec_start + TLS_RECORD_HDR + off, piece);
  }
  for (i = 0, off = 0; i < n; i++, off += limit) {
    piece = len - off < limit ? len - off : limit;
    seal_record(t, t->tx + t->rec_start + i * stride, piece);
  }
  t->tx_len = (uint16_t)(t->rec_start + (n - 1) * stride +
                         (len - (n - 1) * limit) + record_overhead(t));
  t->rec_start = NO_REC;
}

uint8_t *tls_rec_room(tls_conn_t *t, uint8_t type, size_t need) {
  size_t over = (t->flags & F_WPROT) ? 1 + TLS_AEAD_TAG_LEN : 0;
  size_t limit = fragment_limit(t), n, extra = over;
  if (t->rec_start != NO_REC) {
    size_t used = (size_t)(t->tx_len - t->rec_start - TLS_RECORD_HDR);
    if (t->rec_type == type && used + need <= limit &&
        t->tx_len + need + over <= t->tx_cap)
      return t->tx + t->tx_len;
    tls_rec_close(t);
  }
  tls_tx_compact(t);
  for (n = need; n > limit; n -= limit)
    extra += TLS_RECORD_HDR + over;
  if (t->tx_len + TLS_RECORD_HDR + need + extra > t->tx_cap)
    return NULL;
  t->rec_start = t->tx_len;
  t->rec_type = type;
  t->tx_len = (uint16_t)(t->tx_len + TLS_RECORD_HDR);
  return t->tx + t->tx_len;
}

uint8_t *tls_hs_begin(tls_conn_t *t, size_t max) {
  return tls_rec_room(t, TLS_CT_HANDSHAKE, max);
}

void tls_hs_end(tls_conn_t *t, uint8_t *m, uint8_t type, size_t body) {
  m[0] = type;
  net_write24be(m + 1, (uint32_t)body);
  t->cfg->crypto->hash_update(&t->transcript, m, HS_HDR + body);
  t->tx_len = (uint16_t)(t->tx_len + HS_HDR + body);
}

int tls_queue_ccs(tls_conn_t *t) {
  static const uint8_t ccs_record[6] = {
      TLS_CT_CHANGE_CIPHER_SPEC, 3, 3, 0, 1, 1};
  tls_tx_compact(t);
  if (t->tx_len + sizeof(ccs_record) > t->tx_cap)
    return -1;
  memcpy(t->tx + t->tx_len, ccs_record, sizeof(ccs_record));
  t->tx_len = (uint16_t)(t->tx_len + sizeof(ccs_record));
  return 0;
}

static int send_alert(tls_conn_t *t, uint8_t level, uint8_t desc) {
  uint8_t *p = tls_rec_room(t, TLS_CT_ALERT, 2);
  if (!p)
    return -1;
  p[0] = level;
  p[1] = desc;
  t->tx_len = (uint16_t)(t->tx_len + 2);
  tls_rec_close(t);
  return 0;
}

int tls_fail(tls_conn_t *t, int alert) {
  if (t->rec_start != NO_REC) { /* drop a half-built record */
    t->tx_len = t->rec_start;
    t->rec_start = NO_REC;
  }
  (void)send_alert(t, ALERT_FATAL, (uint8_t)alert); /* if tx has room */
  t->state = TLS_STATE_ERROR;
  t->alert = (uint8_t)alert;
  wipe_keys(t);
  tls_notify(t, TLS_EVT_ERROR);
  return -alert;
}

/* ── Handshake messages ── */

/* RFC 8446 §4.6.3: the peer's next keys; answer if asked */
static int on_key_update(tls_conn_t *t, const uint8_t *m, size_t mlen) {
  if (mlen != HS_HDR + 1)
    return tls_fail(t, TLS_ALERT_DECODE_ERROR);
  if (m[HS_HDR] > 1)
    return tls_fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
  tls_update_secret(t->cfg->crypto, t->rsec);
  tls_traffic_keys(t->cfg->crypto, t->rsec, &t->rkeys);
  if (m[HS_HDR])
    t->flags |= F_KU_OWED;
  return HS_KEYS;
}

/* One whole handshake message: HS_*, 0, or < 0 */
static int on_handshake(tls_conn_t *t, const uint8_t *m, size_t mlen) {
  if (t->state != TLS_STATE_CONNECTED)
    return t->role->on_message(t, m, mlen);
  if (m[0] == TLS_HS_KEY_UPDATE)
    return on_key_update(t, m, mlen);
  /* tickets are for resumption, which a client here does not do */
  if (m[0] == TLS_HS_NEW_SESSION_TICKET && !(t->flags & F_SERVER))
    return 0;
  return tls_fail(t, TLS_ALERT_UNEXPECTED_MESSAGE);
}

static void send_owed_key_update(tls_conn_t *t) {
  uint8_t *m = tls_hs_begin(t, HS_HDR + 1);
  if (!m)
    return; /* once tx has room */
  m[HS_HDR] = (t->flags & F_KU_REQ) ? 1 : 0;
  tls_hs_end(t, m, TLS_HS_KEY_UPDATE, 1);
  tls_rec_close(t);
  tls_update_secret(t->cfg->crypto, t->wsec);
  tls_traffic_keys(t->cfg->crypto, t->wsec, &t->wkeys);
  t->flags &= (uint16_t) ~(F_KU_OWED | F_KU_REQ);
}

/* Produce whatever output is due; runs after every input and drain */
static int pump(tls_conn_t *t) {
  int r = 0;
  if (t->state == TLS_STATE_HANDSHAKE)
    r = t->role->pump(t);
  if (r == 0 && (t->flags & F_KU_OWED) && !(t->flags & F_WCLOSED))
    send_owed_key_update(t);
  tls_rec_close(t);
  if (r == 0 && t->state == TLS_STATE_HANDSHAKE && SENDING(t->step) &&
      t->tx_len == t->tx_sent)
    return tls_fail(t, TLS_ALERT_INTERNAL_ERROR); /* tx too small */
  return r;
}

/* ── Receiving ── */

/* rx: [handshake bytes (hs_len) | records not yet processed] */

/* Replace the record at rx + hs_len (@p rlen bytes) by the @p n content
 * bytes at its offset @p off */
static void rx_keep(tls_conn_t *t, size_t off, size_t n, size_t rlen) {
  uint8_t *rec = t->rx + t->hs_len;
  memmove(rec, rec + off, n);
  memmove(rec + n, rec + rlen, (size_t)(t->rx_len - t->hs_len) - rlen);
  t->hs_len = (uint16_t)(t->hs_len + n);
  t->rx_len = (uint16_t)(t->rx_len - (rlen - n));
}

static int on_alert(tls_conn_t *t, const uint8_t *a, size_t n, size_t rlen) {
  uint8_t desc;
  if (n != 2)
    return tls_fail(t, TLS_ALERT_DECODE_ERROR);
  desc = a[1];
  rx_keep(t, 0, 0, rlen);
  if (desc == TLS_ALERT_USER_CANCELED) /* close_notify follows */
    return 0;
  if (desc == TLS_ALERT_CLOSE_NOTIFY) {
    t->state = TLS_STATE_CLOSED;
    tls_notify(t, TLS_EVT_CLOSED);
    return 0;
  }
  t->state = TLS_STATE_ERROR;
  t->alert = desc;
  wipe_keys(t);
  tls_notify(t, TLS_EVT_ERROR);
  return -(int)desc;
}

/* A protected record: handshake bytes, an alert, or application data */
static int on_protected_record(tls_conn_t *t, uint8_t *rec, size_t rlen) {
  uint8_t type;
  int n = tls_record_open(t->cfg->crypto, &t->rkeys, rec, rlen, &type);
  if (n < 0)
    return tls_fail(t, -n);
  if (type == TLS_CT_HANDSHAKE && n > 0) {
    rx_keep(t, TLS_RECORD_HDR, (size_t)n, rlen);
    return 0;
  }
  if (type == TLS_CT_ALERT)
    return on_alert(t, rec + TLS_RECORD_HDR, (size_t)n, rlen);
  /* application data: only between complete handshake messages */
  if (type != TLS_CT_APPLICATION_DATA || t->hs_len ||
      t->state != TLS_STATE_CONNECTED)
    return tls_fail(t, TLS_ALERT_UNEXPECTED_MESSAGE);
  if (n == 0) {
    rx_keep(t, 0, 0, rlen);
    return 0;
  }
  t->app_off = TLS_RECORD_HDR;
  t->app_len = (uint16_t)n;
  t->app_rec = (uint16_t)rlen;
  return 0;
}

/* One whole record at rx + hs_len (a known content type: process()) */
static int on_record(tls_conn_t *t, size_t rlen) {
  uint8_t *rec = t->rx + t->hs_len;
  size_t len = rlen - TLS_RECORD_HDR;

  switch (rec[0]) {
  case TLS_CT_CHANGE_CIPHER_SPEC: /* RFC 8446 §5: dropped, once allowed */
    if (!(t->flags & F_CCS_OK) || len != 1 || rec[TLS_RECORD_HDR] != 0x01)
      return tls_fail(t, TLS_ALERT_UNEXPECTED_MESSAGE);
    rx_keep(t, 0, 0, rlen);
    return 0;
  case TLS_CT_ALERT: /* plaintext: before our keys reach the peer */
    if ((t->flags & F_RPROT) && t->state != TLS_STATE_HANDSHAKE)
      return tls_fail(t, TLS_ALERT_UNEXPECTED_MESSAGE);
    return on_alert(t, rec + TLS_RECORD_HDR, len, rlen);
  case TLS_CT_HANDSHAKE:
    if ((t->flags & F_RPROT) || len == 0)
      return tls_fail(t, TLS_ALERT_UNEXPECTED_MESSAGE);
    rx_keep(t, TLS_RECORD_HDR, len, rlen);
    return 0;
  default:
    if (!(t->flags & F_RPROT))
      return tls_fail(t, TLS_ALERT_UNEXPECTED_MESSAGE);
    return on_protected_record(t, rec, rlen);
  }
}

/* The whole handshake messages collected in rx; 0, or < 0 */
static int process_handshake_messages(tls_conn_t *t) {
  while (t->hs_len - t->hs_off >= HS_HDR) {
    uint8_t *m = t->rx + t->hs_off;
    size_t from, n, mlen = HS_HDR + net_read24be(m + 1);
    int r;
    if (mlen > (size_t)(t->rx_cap - t->hs_off))
      return tls_fail(t, TLS_ALERT_RECORD_OVERFLOW);
    if ((size_t)(t->hs_len - t->hs_off) < mlen)
      return 0;
    if ((r = on_handshake(t, m, mlen)) < 0)
      return r;
    if (r == HS_KEEP) {
      t->hs_off = (uint16_t)(t->hs_off + mlen);
      continue;
    }
    /* drop the message (and the kept one before it, when released) */
    from = r == HS_RELEASE ? 0 : t->hs_off;
    n = t->hs_off + mlen - from;
    memmove(t->rx + from, t->rx + from + n, t->rx_len - from - n);
    t->hs_len = (uint16_t)(t->hs_len - n);
    t->rx_len = (uint16_t)(t->rx_len - n);
    if (r == HS_RELEASE)
      t->hs_off = 0;
    /* RFC 8446 §5.1: a key change falls on a record boundary */
    if (r == HS_KEYS && t->hs_len)
      return tls_fail(t, TLS_ALERT_UNEXPECTED_MESSAGE);
    if ((r = pump(t)) < 0)
      return r;
  }
  return 0;
}

/* Work through rx: whole handshake messages, then whole records.  A
 * record header is checked before its body is awaited. */
static int process(tls_conn_t *t) {
  for (;;) {
    const uint8_t *hdr;
    size_t avail, rlen;
    int r;
    if (t->state != TLS_STATE_HANDSHAKE && t->state != TLS_STATE_CONNECTED)
      return t->state == TLS_STATE_ERROR ? -(int)t->alert : 0;
    if (t->app_len) /* the reader first */
      return 0;
    if ((r = process_handshake_messages(t)) < 0)
      return r;

    avail = (size_t)(t->rx_len - t->hs_len);
    if (avail < TLS_RECORD_HDR)
      return 0;
    hdr = t->rx + t->hs_len;
    if (hdr[0] < TLS_CT_CHANGE_CIPHER_SPEC || hdr[0] > TLS_CT_APPLICATION_DATA)
      return tls_fail(t, TLS_ALERT_UNEXPECTED_MESSAGE);
    rlen = net_read16be(hdr + 3);
    if (rlen > (hdr[0] == TLS_CT_APPLICATION_DATA ? TLS_MAX_CIPHERTEXT
                                                  : TLS_MAX_PLAINTEXT))
      return tls_fail(t, TLS_ALERT_RECORD_OVERFLOW);
    rlen += TLS_RECORD_HDR;
    if (rlen > (size_t)(t->rx_cap - t->hs_len))
      return tls_fail(t, TLS_ALERT_RECORD_OVERFLOW);
    if (avail < rlen)
      return 0;
    if ((r = on_record(t, rlen)) < 0)
      return r;
  }
}

int tls_init(tls_conn_t *t, const tls_config_t *cfg, uint8_t *rx, size_t rx_cap,
             uint8_t *tx, size_t tx_cap) {
  if (!t || !cfg || !cfg->crypto || !rx || !tx || rx_cap < BUF_MIN ||
      tx_cap < BUF_MIN)
    return -1;
  memset(t, 0, sizeof(*t));
  t->cfg = cfg;
  t->rx = rx;
  t->rx_cap = (uint16_t)(rx_cap > BUF_MAX ? BUF_MAX : rx_cap);
  t->tx = tx;
  t->tx_cap = (uint16_t)(tx_cap > BUF_MAX ? BUF_MAX : tx_cap);
  t->rec_start = NO_REC;
  return 0;
}

size_t tls_rx_space(tls_conn_t *t, uint8_t **buf) {
  *buf = t->rx + t->rx_len;
  return (size_t)(t->rx_cap - t->rx_len);
}

int tls_rx_commit(tls_conn_t *t, size_t n) {
  int r;
  if (n > (size_t)(t->rx_cap - t->rx_len))
    n = (size_t)(t->rx_cap - t->rx_len);
  t->rx_len = (uint16_t)(t->rx_len + n);
  if (t->state != TLS_STATE_HANDSHAKE && t->state != TLS_STATE_CONNECTED) {
    t->rx_len = t->hs_len; /* after close_notify or an error: discarded */
    return t->state == TLS_STATE_ERROR ? -(int)t->alert : 0;
  }
  r = process(t);
  return r < 0 ? r : pump(t);
}

size_t tls_input(tls_conn_t *t, const uint8_t *data, size_t len) {
  size_t used = 0;
  while (used < len) {
    uint8_t *p;
    size_t n = tls_rx_space(t, &p);
    if (n > len - used)
      n = len - used;
    if (n == 0)
      break;
    memcpy(p, data + used, n);
    used += n;
    if (tls_rx_commit(t, n) < 0)
      break;
  }
  return used;
}

size_t tls_tx_pending(tls_conn_t *t, const uint8_t **buf) {
  *buf = t->tx + t->tx_sent;
  return (size_t)(t->tx_len - t->tx_sent);
}

void tls_tx_done(tls_conn_t *t, size_t n) {
  if (n > (size_t)(t->tx_len - t->tx_sent))
    n = (size_t)(t->tx_len - t->tx_sent);
  t->tx_sent = (uint16_t)(t->tx_sent + n);
  if (t->tx_sent == t->tx_len)
    t->tx_len = t->tx_sent = 0;
  if (t->state == TLS_STATE_HANDSHAKE || t->state == TLS_STATE_CONNECTED)
    (void)pump(t);
}

static int writable(const tls_conn_t *t) {
  return (t->state == TLS_STATE_CONNECTED || t->state == TLS_STATE_CLOSED) &&
         !(t->flags & F_WCLOSED);
}

int tls_write(tls_conn_t *t, const uint8_t *data, size_t len) {
  uint8_t *p;
  size_t room;
  if (!writable(t))
    return -1;
  if (t->wkeys.seq >= TLS_KEY_UPDATE_RECORDS) { /* RFC 8446 §5.5 */
    t->flags |= F_KU_OWED;
    (void)pump(t);
    if (t->flags & F_KU_OWED)
      return 0; /* no room for it yet */
  }
  tls_tx_compact(t);
  room = (size_t)(t->tx_cap - t->tx_len);
  if (room <= TLS_RECORD_OVERHEAD)
    return 0;
  room -= TLS_RECORD_OVERHEAD;
  if (len > room)
    len = room;
  if (len > fragment_limit(t))
    len = fragment_limit(t);
  p = tls_rec_room(t, TLS_CT_APPLICATION_DATA, len);
  memcpy(p, data, len);
  t->tx_len = (uint16_t)(t->tx_len + len);
  tls_rec_close(t);
  return (int)len;
}

size_t tls_read(tls_conn_t *t, uint8_t *buf, size_t len) {
  if (!t->app_len)
    return 0;
  if (len > t->app_len)
    len = t->app_len;
  memcpy(buf, t->rx + t->app_off, len);
  t->app_off = (uint16_t)(t->app_off + len);
  t->app_len = (uint16_t)(t->app_len - len);
  if (!t->app_len) { /* the record is used up: on to the next */
    rx_keep(t, 0, 0, t->app_rec);
    t->app_rec = 0;
    if (process(t) >= 0)
      (void)pump(t);
  }
  return len;
}

int tls_psk_used(const tls_conn_t *t) { return (t->flags & F_PSK) != 0; }

int tls_key_update(tls_conn_t *t, int request) {
  if (!writable(t))
    return -1;
  t->flags |= F_KU_OWED | (request ? F_KU_REQ : 0u);
  (void)pump(t); /* now, or once tx has room */
  return 0;
}

int tls_close(tls_conn_t *t) {
  if (t->flags & F_WCLOSED)
    return 0;
  if (t->state == TLS_STATE_IDLE || t->state == TLS_STATE_ERROR)
    return -1;
  if (send_alert(t, ALERT_WARNING, TLS_ALERT_CLOSE_NOTIFY) != 0)
    return -1;
  t->flags |= F_WCLOSED;
  return 0;
}
