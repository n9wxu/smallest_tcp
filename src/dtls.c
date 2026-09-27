/**
 * @file dtls.c
 * @brief DTLS 1.3 (RFC 9147): the datagram record layer — records, the
 *        handshake's flights, fragmentation and reassembly, the
 *        retransmission timer, ACKs, KeyUpdate — and the API.  The
 *        handshake itself is TLS's (tls_server.c, tls_client.c), reached
 *        through tls_common.c.  See docs/design/dtls.md.
 *
 * No cryptography here (REQ-DTLS-070): AES-GCM, the AES block for record
 * numbers and HKDF come from the tls_crypto_t backend.
 *
 * No division: this builds for Cortex-M0.
 */

#include "dtls.h"
#include "tls_internal.h"

#if !TLS_USE_DTLS
#error "dtls.c needs the handshake built with TLS_USE_DTLS"
#endif

/* The first byte of a DTLSCiphertext header (RFC 9147 §4, Figure 3) */
#define HDR_FIXED 0x20u /* 001 */
#define HDR_FIXED_MASK 0xE0u
#define HDR_CID 0x10u
#define HDR_SEQ16 0x08u
#define HDR_LEN 0x04u
#define HDR_EPOCH 0x03u

#define REPLAY_WINDOW 32u

/* ── Records (§4) ── */

void dtls_keys_derive(const tls_crypto_t *c, const uint8_t secret[TLS_HASH_LEN],
                      dtls_keys_t *k) {
  tls_traffic_keys(c, 1, secret, &k->k);
  tls_expand_label(c, 1, secret, "sn", NULL, 0, k->sn, TLS_AEAD_KEY_LEN);
  k->window = 0;
}

/* The per-record nonce: the IV XOR the 64-bit record number (§4: the
 * epoch is not in it — each epoch has its own keys) */
static void record_nonce(const dtls_keys_t *k, uint64_t seq,
                         uint8_t nonce[TLS_AEAD_IV_LEN]) {
  int i;
  memcpy(nonce, k->k.iv, TLS_AEAD_IV_LEN);
  for (i = TLS_AEAD_IV_LEN - 1; i >= TLS_AEAD_IV_LEN - 8; i--) {
    nonce[i] ^= (uint8_t)seq;
    seq >>= 8;
  }
}

size_t dtls_record_seal(const tls_crypto_t *c, dtls_keys_t *k, uint16_t epoch,
                        uint8_t type, uint8_t *rec, size_t len) {
  uint8_t nonce[TLS_AEAD_IV_LEN], mask[16];
  uint8_t *inner = rec + DTLS_RECORD_HDR;
  size_t clen = len + 1 + TLS_AEAD_TAG_LEN;

  inner[len] = type; /* DTLSInnerPlaintext: content, type, no padding */
  rec[0] = (uint8_t)(HDR_FIXED | HDR_SEQ16 | HDR_LEN | (epoch & HDR_EPOCH));
  net_write16be(rec + 1, (uint16_t)k->k.seq);
  net_write16be(rec + 3, (uint16_t)clen);
  record_nonce(k, k->k.seq, nonce);
  /* the header goes into the AAD before its record number is masked */
  c->aead_seal(k->k.key, nonce, rec, DTLS_RECORD_HDR, inner, len + 1, inner,
               inner + len + 1);
  c->aes_block(k->sn, inner, mask); /* at least 17 bytes of ciphertext */
  rec[1] ^= mask[0];
  rec[2] ^= mask[1];
  k->k.seq++;
  return DTLS_RECORD_HDR + clen;
}

int dtls_record_parse(const uint8_t *in, size_t avail, dtls_rec_t *r) {
  size_t h;
  if (avail < 2 || (in[0] & HDR_FIXED_MASK) != HDR_FIXED ||
      (in[0] & HDR_CID)) /* no CID was negotiated (§9.1) */
    return -1;
  h = (in[0] & HDR_SEQ16) ? 3u : 2u;
  if (in[0] & HDR_LEN) {
    if (avail < h + 2)
      return -1;
    r->len = net_read16be(in + h);
    h += 2;
    if (r->len > avail - h)
      return -1;
  } else { /* the rest of the datagram */
    if (avail < h || avail - h > 0xFFFFu)
      return -1;
    r->len = (uint16_t)(avail - h);
  }
  r->hlen = (uint8_t)h;
  r->epoch = (uint8_t)(in[0] & HDR_EPOCH);
  return 0;
}

uint64_t dtls_seq_expand(uint64_t next, uint32_t bits, unsigned nbits) {
  uint64_t win = nbits == 8 ? 0x100u : 0x10000u, hwin = win >> 1;
  uint64_t cand = (next & ~(win - 1)) | bits;
  if (cand + hwin <= next) /* too far behind: it is in the next window */
    return cand + win;
  if (cand > next + hwin && cand >= win) /* too far ahead: the one before */
    return cand - win;
  return cand;
}

/* §4.5.1: a record number already taken, or below the window */
static int replayed(const dtls_keys_t *k, uint64_t seq) {
  uint64_t behind;
  if (seq >= k->k.seq)
    return 0;
  behind = k->k.seq - 1 - seq;
  return behind >= REPLAY_WINDOW || ((k->window >> behind) & 1u);
}

static void mark_taken(dtls_keys_t *k, uint64_t seq) {
  if (seq >= k->k.seq) {
    uint64_t shift = seq + 1 - k->k.seq;
    k->window = shift >= REPLAY_WINDOW ? 0 : k->window << shift;
    k->window |= 1u;
    k->k.seq = seq + 1;
  } else {
    k->window |= 1ul << (k->k.seq - 1 - seq);
  }
}

int dtls_record_open(const tls_crypto_t *c, dtls_keys_t *k, const uint8_t *in,
                     const dtls_rec_t *r, uint8_t *out, uint8_t *type,
                     uint64_t *seq) {
  uint8_t mask[16], aad[DTLS_RECORD_HDR], nonce[TLS_AEAD_IV_LEN];
  size_t n, h = r->hlen;
  uint64_t s;

  /* §4.2.3: the mask needs 16 bytes of ciphertext; TLS's bound on
   * DTLSInnerPlaintext applies too */
  if (r->len < 16 || (size_t)r->len - TLS_AEAD_TAG_LEN > TLS_MAX_PLAINTEXT + 1)
    return -1;
  c->aes_block(k->sn, in + h, mask);
  memcpy(aad, in, h);
  aad[1] ^= mask[0];
  if (in[0] & HDR_SEQ16) {
    aad[2] ^= mask[1];
    s = dtls_seq_expand(k->k.seq, ((uint32_t)aad[1] << 8) | aad[2], 16);
  } else {
    s = dtls_seq_expand(k->k.seq, aad[1], 8);
  }
  n = r->len - TLS_AEAD_TAG_LEN;
  record_nonce(k, s, nonce);
  if (c->aead_open(k->k.key, nonce, aad, h, in + h, n, in + h + n, out) != 0)
    return -1;
  /* after deprotection, so that a discard is no timing channel (§4.5.1) */
  if (replayed(k, s))
    return -1;
  mark_taken(k, s);
  while (n > 0 && out[n - 1] == 0) /* strip the padding */
    n--;
  if (n == 0)
    return -1;
  *type = out[--n];
  *seq = s;
  return (int)n;
}

/* ── Connections ── */

#define PLAIN_HDR 13 /* DTLSPlaintext: type, version, epoch, seq48, len */
#define FRAG_HDR 12  /* the DTLS handshake header (§5.2) */
#define MIN_FRAG 16u /* a smaller piece waits for the next datagram */
#define DG_MIN 64u   /* room a flight must leave for a datagram */
#define NO_SPLIT 0xFFFFu
#define LAST_EPOCH 0xFFFFu
#define LAST_PASS 7u
#define BUF_MIN 256u
#define BUF_MAX 0xFFFEu

/* dtls_conn_t.fl_state: the flight in tls.tx[0 .. tls.tx_len) */
enum {
  FL_NONE,    /* none: the store is empty */
  FL_NEW,     /* being written; not sent yet */
  FL_SENDING, /* a transmission is under way */
  FL_WAITING  /* sent: the timer runs until it is answered */
};

static dtls_conn_t *dtls_of(tls_conn_t *t) { return (dtls_conn_t *)(void *)t; }

static const tls_crypto_t *crypto(const dtls_conn_t *d) {
  return d->tls.cfg->crypto;
}

static int writable(const tls_conn_t *t) {
  return (t->state == TLS_STATE_CONNECTED || t->state == TLS_STATE_CLOSED) &&
         !(t->flags & F_WCLOSED);
}

/* ── The flight ── */

static uint16_t epoch_at(const dtls_conn_t *d, size_t off) {
  return off < d->fl_split ? d->fl_ep[0] : d->fl_ep[1];
}

static uint16_t flight_messages(const dtls_conn_t *d) {
  const tls_conn_t *t = &d->tls;
  size_t off;
  uint16_t n = 0;
  for (off = 0; off < t->tx_len; off += HS_HDR + net_read24be(t->tx + off + 1))
    n++;
  return n;
}

/* The flight is over: its messages leave the store (the datagram waiting
 * after them moves down) and message_seq moves past them */
static void flight_done(dtls_conn_t *d) {
  tls_conn_t *t = &d->tls;
  d->fl_seq = (uint16_t)(d->fl_seq + flight_messages(d));
  memmove(t->tx, t->tx + t->tx_len, d->dg_len);
  t->tx_len = 0;
  d->fl_state = FL_NONE;
  d->timer_ms = 0;
}

/* Nothing more of the flight, nor the datagram waiting, is sent */
static void abandon(dtls_conn_t *d) {
  d->fl_state = FL_NONE;
  d->timer_ms = 0;
  d->tls.tx_len = 0;
  d->dg_len = 0;
}

/* A transmission of the flight: the first (@p again 0) or another */
static void transmit(dtls_conn_t *d, int again) {
  if (!again) {
    d->pass = d->pass_lost = d->sent_n = d->retries = 0;
    d->rto_ms = DTLS_RTO_INITIAL_MS;
  } else if (d->pass < LAST_PASS) {
    d->pass++;
  } else {
    d->pass_lost |= 1u << LAST_PASS; /* no more passes to tell apart */
  }
  d->fl_pos = d->fl_idx = d->fl_frag = 0;
  d->fl_state = FL_SENDING;
  d->timer_ms = 0;
}

/* The peer has our flight: no more retransmissions.  A KeyUpdate of ours
 * takes effect only now (RFC 9147 §8) */
static void flight_acked(dtls_conn_t *d) {
  tls_conn_t *t = &d->tls;
  if (d->fl_state != FL_SENDING && d->fl_state != FL_WAITING)
    return;
  flight_done(d);
  if (t->flags & F_KU_SENT) {
    t->flags &= (uint16_t)~F_KU_SENT;
    tls_update_secret(crypto(d), 1, t->wsec);
    tls_set_keys(t, 1);
  }
}

static void timed_out(dtls_conn_t *d) {
  tls_conn_t *t = &d->tls;
  abandon(d);
  t->state = TLS_STATE_ERROR;
  t->alert = DTLS_TIMEOUT;
  tls_wipe_keys(t);
  tls_notify(t, TLS_EVT_ERROR);
}

/* ── The record layer the roles write through ── */

static uint8_t *hs_begin(tls_conn_t *t, size_t max) {
  dtls_conn_t *d = dtls_of(t);
  if (d->dg_len || d->fl_state == FL_SENDING || d->fl_state == FL_WAITING)
    return NULL;                /* after the datagram, or the flight's answer */
  if (d->fl_state == FL_NONE) { /* the first message of a flight */
    d->fl_state = FL_NEW;
    d->fl_split = NO_SPLIT;
    d->fl_ep[0] = d->wepoch;
    /* a handshake flight answers the peer's: its records after this belong
     * to its next flight (§7).  After the handshake, flights each way are
     * independent (§5.8.4). */
    if (t->state == TLS_STATE_HANDSHAKE)
      d->ack_n = 0;
  } else if (epoch_at(d, t->tx_len) != d->wepoch) { /* its keys changed */
    if (d->fl_split != NO_SPLIT)
      return NULL;
    d->fl_split = t->tx_len;
    d->fl_ep[1] = d->wepoch;
  }
  if (t->tx_len + max + DG_MIN > t->tx_cap)
    return NULL;
  return t->tx + t->tx_len;
}

/* A flight goes when the handshake has written all of it (pump()) */
static void hs_flush(tls_conn_t *t) { (void)t; }

/* Never called: a DTLS server keeps no session id, so it never owes the
 * compatibility-mode change_cipher_spec */
static int no_ccs(tls_conn_t *t) {
  (void)t;
  return 0;
}

static size_t dg_space(const dtls_conn_t *d) {
  const tls_conn_t *t = &d->tls;
  size_t room = (size_t)(t->tx_cap - t->tx_len);
  if (room > d->mtu)
    room = d->mtu;
  return room > d->dg_len ? room - d->dg_len : 0;
}

/* Our record numbers in the flight, for its ACK */
static void track(dtls_conn_t *d, uint16_t epoch, uint64_t seq) {
  if (d->sent_n == DTLS_SENT_MAX) {
    d->pass_lost |= (uint8_t)(1u << d->pass);
    return;
  }
  d->sent[d->sent_n].epoch = epoch;
  d->sent[d->sent_n].seq = (uint32_t)seq;
  d->sent[d->sent_n].pass = d->pass;
  d->sent[d->sent_n].acked = 0;
  d->sent_n++;
}

/* Finish the record at @p rec, whose @p len content bytes follow its
 * header: sealed under our keys for @p epoch, or DTLSPlaintext for epoch
 * 0.  Returns its length. */
static size_t close_record(dtls_conn_t *d, uint8_t *rec, uint16_t epoch,
                           uint8_t type, size_t len, int tracked) {
  if (epoch) {
    dtls_keys_t *k = epoch == d->wepoch ? &d->w : &d->w_prev;
    if (tracked)
      track(d, epoch, k->k.seq);
    return dtls_record_seal(crypto(d), k, epoch, type, rec, len);
  }
  if (tracked)
    track(d, 0, d->pseq);
  rec[0] = type;
  net_write16be(rec + 1, DTLS_LEGACY_VERSION);
  memset(rec + 3, 0, 6); /* epoch 0, the top of the record number */
  net_write16be(rec + 9, d->pseq++);
  net_write16be(rec + 11, (uint16_t)len);
  return PLAIN_HDR + len;
}

static size_t record_header(uint16_t epoch) {
  return epoch ? DTLS_RECORD_HDR : PLAIN_HDR;
}

static size_t record_overhead(uint16_t epoch) {
  return epoch ? DTLS_RECORD_OVERHEAD : PLAIN_HDR;
}

/* An alert, in the datagram waiting or a new one; -1 if neither has room.
 * Alerts are sent once (§5.10). */
static int queue_alert(dtls_conn_t *d, uint8_t level, uint8_t desc) {
  uint16_t epoch = (d->tls.flags & F_WPROT) ? d->wepoch : 0;
  uint8_t *rec = d->tls.tx + d->tls.tx_len + d->dg_len;
  if (dg_space(d) < record_overhead(epoch) + 2)
    return -1;
  rec[record_header(epoch)] = level;
  rec[record_header(epoch) + 1] = desc;
  d->dg_len =
      (uint16_t)(d->dg_len + close_record(d, rec, epoch, TLS_CT_ALERT, 2, 0));
  return 0;
}

/* tls_fail(): the handshake stops; only the alert goes */
static void fail_alert(tls_conn_t *t, uint8_t level, uint8_t desc) {
  dtls_conn_t *d = dtls_of(t);
  abandon(d);
  (void)queue_alert(d, level, desc);
}

/* The next epoch's keys; the current ones stay, as the previous epoch's:
 * a flight is retransmitted under its own keys (§4.2.1), and the peer's
 * records may still come under the old ones (§8) */
static void set_keys(tls_conn_t *t, int write) {
  dtls_conn_t *d = dtls_of(t);
  uint16_t *epoch = write ? &d->wepoch : &d->repoch;
  if (*epoch == LAST_EPOCH) { /* epochs never wrap (§6.1) */
    (void)tls_fail(t, TLS_ALERT_INTERNAL_ERROR);
    return;
  }
  if (write) {
    d->w_prev = d->w;
    dtls_keys_derive(crypto(d), t->wsec, &d->w);
  } else {
    d->r_prev = d->r;
    dtls_keys_derive(crypto(d), t->rsec, &d->r);
  }
  *epoch = (uint16_t)(*epoch ? *epoch + 1 : 2); /* no epoch 1: no 0-RTT */
}

static void wipe(tls_conn_t *t) {
  dtls_conn_t *d = dtls_of(t);
  tls_wipe(&d->r, sizeof(d->r));
  tls_wipe(&d->w, sizeof(d->w));
  tls_wipe(&d->r_prev, sizeof(d->r_prev));
  tls_wipe(&d->w_prev, sizeof(d->w_prev));
}

static const tls_rl_t dtls_rl = {1,          hs_begin, hs_flush, no_ccs,
                                 fail_alert, set_keys, wipe};

/* ── Sending ── */

static void send_key_update(dtls_conn_t *d) {
  tls_conn_t *t = &d->tls;
  uint8_t *m;
  if (d->wepoch == LAST_EPOCH) { /* no update past the last epoch (§8) */
    t->flags &= (uint16_t) ~(F_KU_OWED | F_KU_REQ | F_KU_ANS);
    return;
  }
  if (!(m = tls_hs_begin(t, HS_HDR + 1)))
    return; /* once the flight before it is answered */
  /* an answer never asks back (RFC 8446 §4.6.3) */
  m[HS_HDR] = (t->flags & (F_KU_REQ | F_KU_ANS)) == F_KU_REQ;
  tls_hs_end(t, m, TLS_HS_KEY_UPDATE, 1);
  t->flags =
      (uint16_t)((t->flags & ~(F_KU_OWED | F_KU_REQ | F_KU_ANS)) | F_KU_SENT);
}

/* Produce whatever is due: the handshake's messages, an owed KeyUpdate;
 * a flight just written starts its first transmission */
static int pump(dtls_conn_t *d) {
  tls_conn_t *t = &d->tls;
  int r = 0;
  if (t->state == TLS_STATE_HANDSHAKE)
    r = t->role->pump(t);
  if (r == 0 && (t->flags & F_KU_OWED) && writable(t) &&
      !(t->flags & F_KU_SENT))
    send_key_update(d);
  if (d->fl_state == FL_NEW)
    transmit(d, 0);
  if (r == 0 && t->state == TLS_STATE_HANDSHAKE && SENDING(t->step) &&
      !d->dg_len)
    return tls_fail(t, TLS_ALERT_INTERNAL_ERROR); /* tx too small */
  return r;
}

/* The ACK owed: the peer's records we took, newest last (§7) */
static void add_ack(dtls_conn_t *d) {
  size_t n = d->ack_n, i;
  uint8_t *rec = d->tls.tx + d->tls.tx_len + d->dg_len, *p;
  while (n && dg_space(d) < DTLS_RECORD_OVERHEAD + 2 + 16 * n)
    n--;
  if (dg_space(d) < DTLS_RECORD_OVERHEAD + 2 + 16 * n)
    return;
  p = rec + DTLS_RECORD_HDR;
  net_write16be(p, (uint16_t)(16 * n));
  p += 2;
  for (i = d->ack_n - n; i < d->ack_n; i++, p += 16) {
    memset(p, 0, 16);
    net_write16be(p + 6, d->acks[i].epoch);
    net_write32be(p + 12, d->acks[i].seq);
  }
  d->dg_len = (uint16_t)(d->dg_len + close_record(d, rec, d->wepoch,
                                                  DTLS_CT_ACK, 2 + 16 * n, 0));
  d->ack_owed = 0;
}

/* Cut the transmission's next messages into handshake fragments, in
 * records of their epoch, until the datagram is full (§5.5) */
static void add_fragments(dtls_conn_t *d) {
  tls_conn_t *t = &d->tls;
  size_t limit = t->max_frag ? t->max_frag : TLS_MAX_PLAINTEXT;
  while (d->fl_pos < t->tx_len) {
    uint16_t epoch = epoch_at(d, d->fl_pos);
    uint8_t *rec = t->tx + t->tx_len + d->dg_len;
    uint8_t *body = rec + record_header(epoch);
    size_t cap = dg_space(d), used = 0;
    if (cap <= record_overhead(epoch))
      break;
    cap -= record_overhead(epoch);
    if (cap > limit)
      cap = limit;
    while (d->fl_pos < t->tx_len && epoch_at(d, d->fl_pos) == epoch) {
      const uint8_t *m = t->tx + d->fl_pos;
      size_t mlen = net_read24be(m + 1), left = mlen - d->fl_frag, k;
      if (cap - used < FRAG_HDR + (left < MIN_FRAG ? left : MIN_FRAG))
        break;
      k = cap - used - FRAG_HDR;
      if (k > left)
        k = left;
      body[used] = m[0];
      net_write24be(body + used + 1, (uint32_t)mlen);
      net_write16be(body + used + 4, (uint16_t)(d->fl_seq + d->fl_idx));
      net_write24be(body + used + 6, d->fl_frag);
      net_write24be(body + used + 9, (uint32_t)k);
      memcpy(body + used + FRAG_HDR, m + HS_HDR + d->fl_frag, k);
      used += FRAG_HDR + k;
      d->fl_frag = (uint16_t)(d->fl_frag + k);
      if (d->fl_frag < mlen)
        break; /* the record is full */
      d->fl_pos = (uint16_t)(d->fl_pos + HS_HDR + mlen);
      d->fl_idx++;
      d->fl_frag = 0;
    }
    if (!used)
      break;
    d->dg_len = (uint16_t)(d->dg_len + close_record(d, rec, epoch,
                                                    TLS_CT_HANDSHAKE, used, 1));
  }
  if (d->fl_pos >= t->tx_len) { /* all of it has gone */
    d->fl_state = FL_WAITING;
    d->timer_ms = d->rto_ms;
  }
}

static void build_datagram(dtls_conn_t *d) {
  if (d->tls.flags & F_WCLOSED)
    return; /* nothing after our close_notify */
  if (d->ack_owed) {
    if (d->tls.flags & F_WPROT)
      add_ack(d);
    else
      d->ack_owed = 0; /* no keys to send it under yet */
  }
  if (d->fl_state == FL_SENDING)
    add_fragments(d);
}

/* ── Receiving ── */

/* rx: [kept message | message being reassembled | read queue | free]
 *     0            hs_off                      hs_len       rx_len    rx_cap
 * The message being reassembled has its TLS header at hs_off and its area
 * reserved to its full length; the queue holds records of application
 * data, each behind a two-byte length. */

/* A record of the peer's we took: for the ACK, in increasing order (§7);
 * when full, the oldest goes */
static void note_record(dtls_conn_t *d, uint16_t epoch, uint64_t seq) {
  size_t i = 0;
  while (i < d->ack_n && (d->acks[i].epoch < epoch ||
                          (d->acks[i].epoch == epoch && d->acks[i].seq < seq)))
    i++;
  if (i < d->ack_n && d->acks[i].epoch == epoch && d->acks[i].seq == seq)
    return;
  if (d->ack_n == DTLS_ACK_MAX) {
    if (i == 0)
      return;
    memmove(d->acks, d->acks + 1, (--i) * sizeof(d->acks[0]));
    d->ack_n--;
  }
  memmove(d->acks + i + 1, d->acks + i, (d->ack_n - i) * sizeof(d->acks[0]));
  d->acks[i].epoch = epoch;
  d->acks[i].seq = (uint32_t)seq;
  d->ack_n++;
}

/* A fragment of the message expected next: 1 placed, 0 not (a gap before
 * it, or no room while data is unread), < 0 failed.  @p limit: where in rx
 * the record holding it begins (rx_cap if not in rx). */
static int place(dtls_conn_t *d, const uint8_t *f, size_t limit) {
  tls_conn_t *t = &d->tls;
  uint32_t mlen = net_read24be(f + 1), off = net_read24be(f + 6);
  uint32_t n = net_read24be(f + 9), same;
  uint8_t *m = t->rx + t->hs_off;
  if (t->hs_len == t->hs_off) { /* its first fragment: reserve it all */
    size_t need = HS_HDR + mlen, queued = (size_t)(t->rx_len - t->hs_len);
    if (t->hs_off + need > limit)
      return tls_fail(t, TLS_ALERT_RECORD_OVERFLOW);
    if (t->hs_off + need + queued > limit)
      return 0;                   /* not until the reader makes room */
    memmove(m + need, m, queued); /* unread data moves up, behind it */
    m[0] = f[0];
    net_write24be(m + 1, mlen);
    t->hs_len = (uint16_t)(t->hs_off + need);
    t->rx_len = (uint16_t)(t->hs_len + queued);
    d->hs_have = 0;
  } else if (m[0] != f[0] || net_read24be(m + 1) != mlen) {
    return 0;
  }
  if (off > d->hs_have)
    return 0;
  /* §5.5: overlapping ranges are fine; changed bytes are not */
  same = (off + n < d->hs_have ? off + n : d->hs_have) - off;
  if (memcmp(m + HS_HDR + off, f + FRAG_HDR, same) != 0)
    return tls_fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
  memcpy(m + HS_HDR + off + same, f + FRAG_HDR + same, n - same);
  if (off + n > d->hs_have)
    d->hs_have = (uint16_t)(off + n);
  return 1;
}

/* The message reassembled: to the handshake, as TLS would take it */
static int message_done(dtls_conn_t *d) {
  tls_conn_t *t = &d->tls;
  size_t from;
  int r, in_handshake = t->state == TLS_STATE_HANDSHAKE;
  d->rx_seq++;
  if (in_handshake)
    flight_acked(d); /* the peer's next flight answers ours (§7) */
  r = tls_on_handshake(t, t->rx + t->hs_off, (size_t)(t->hs_len - t->hs_off));
  if (r < 0)
    return r;
  if (t->state == TLS_STATE_ERROR)
    return -(int)t->alert;
  if (r == HS_KEEP) {
    t->hs_off = t->hs_len;
    return r;
  }
  from = r == HS_RELEASE ? 0 : t->hs_off; /* drop it (and the kept one) */
  memmove(t->rx + from, t->rx + t->hs_len, (size_t)(t->rx_len - t->hs_len));
  t->rx_len = (uint16_t)(t->rx_len - (t->hs_len - from));
  t->hs_off = t->hs_len = (uint16_t)from;
  /* the client's last flight: nothing but an ACK answers it (§5.7) */
  if (in_handshake && t->state == TLS_STATE_CONNECTED && (t->flags & F_SERVER))
    d->ack_owed = 1;
  return r;
}

/* The handshake fragments of one record (@p n bytes at @p p) */
static int on_fragments(dtls_conn_t *d, const uint8_t *p, size_t n,
                        uint16_t epoch, uint64_t seq, size_t limit) {
  tls_conn_t *t = &d->tls;
  int placed = 0, repeated = 0, r;
  int after = t->state != TLS_STATE_HANDSHAKE; /* post-handshake messages */
  while (n >= FRAG_HDR) {
    uint32_t mlen = net_read24be(p + 1), off = net_read24be(p + 6);
    uint32_t len = net_read24be(p + 9);
    uint16_t mseq = net_read16be(p + 4);
    if (len > n - FRAG_HDR || off + len > mlen)
      break; /* malformed: the rest of the record goes too */
    if (mseq < d->rx_seq) {
      repeated = 1;
    } else if (mseq > d->rx_seq) {
      d->ack_owed = 1; /* a later message first: say what we have (§7.1) */
    } else if (!epoch && (t->flags & F_RPROT)) {
      /* a new message in plaintext once the peer's are protected: forged */
    } else if ((r = place(d, p, limit)) < 0) {
      return r;
    } else if (r == 0) {
      d->ack_owed = 1;
    } else {
      if (!placed) /* before the message can start a flight of ours */
        note_record(d, epoch, seq);
      placed = 1;
      if (d->hs_have == mlen) {
        if ((r = message_done(d)) < 0)
          return r;
        /* a key change falls on a record boundary (RFC 8446 §5.1) */
        if (r == HS_KEYS && n > FRAG_HDR + len)
          return tls_fail(t, TLS_ALERT_UNEXPECTED_MESSAGE);
        if ((r = pump(d)) < 0)
          return r;
      }
    }
    p += FRAG_HDR + len;
    n -= FRAG_HDR + len;
  }
  if (placed && after)
    d->ack_owed = 1; /* post-handshake messages are acknowledged (§7.1) */
  if (repeated) {
    if (after && (epoch >= 3 || (t->flags & F_SERVER))) {
      /* our ACK was lost: again (§5.8.1, §7.1) */
      note_record(d, epoch, seq);
      d->ack_owed = 1;
    } else if (d->fl_state == FL_WAITING) {
      transmit(d, 1); /* the peer has not had our flight (§5.8.1) */
    }
  }
  return 0;
}

static void alert_received(dtls_conn_t *d, uint8_t desc) {
  tls_conn_t *t = &d->tls;
  (void)tls_alert_received(t, desc);
  if (t->state == TLS_STATE_ERROR)
    abandon(d);
  else if (t->state == TLS_STATE_CLOSED && d->fl_state != FL_NONE)
    flight_done(d); /* the peer is done: nothing more to retransmit */
}

/* Our records the peer has (§7.2): a transmission all of whose records it
 * names has done its job */
static int flight_answered(const dtls_conn_t *d) {
  unsigned q;
  for (q = 0; q <= d->pass; q++) {
    int any = 0, all = 1;
    size_t j;
    if (((d->pass_lost >> q) & 1u) ||
        (q == d->pass && d->fl_state != FL_WAITING))
      continue;
    for (j = 0; j < d->sent_n; j++)
      if (d->sent[j].pass == q) {
        any = 1;
        all &= d->sent[j].acked;
      }
    if (any && all)
      return 1;
  }
  return 0;
}

static void on_ack(dtls_conn_t *d, const uint8_t *p, size_t n) {
  size_t i, j;
  if (n < 2 || net_read16be(p) != n - 2 || ((n - 2) & 15u))
    return;
  for (i = 2; i < n; i += 16) {
    static const uint8_t zero[6] = {0};
    if (memcmp(p + i, zero, 6) || memcmp(p + i + 8, zero, 4))
      continue; /* not a record of ours */
    for (j = 0; j < d->sent_n; j++)
      if (d->sent[j].epoch == net_read16be(p + i + 6) &&
          d->sent[j].seq == net_read32be(p + i + 12))
        d->sent[j].acked = 1;
  }
  if (flight_answered(d))
    flight_acked(d);
}

/* One DTLSPlaintext record: the bytes it takes, or 0 if the datagram
 * cannot be read further */
static size_t on_plaintext(dtls_conn_t *d, const uint8_t *in, size_t avail) {
  tls_conn_t *t = &d->tls;
  const uint8_t *p = in + PLAIN_HDR;
  size_t n;
  if (avail < PLAIN_HDR || (n = net_read16be(in + 11)) > avail - PLAIN_HDR)
    return 0;
  if (net_read16be(in + 3) != 0) /* only epoch 0 goes unprotected */
    return PLAIN_HDR + n;
  if (in[0] == TLS_CT_HANDSHAKE) {
    uint64_t seq =
        ((uint64_t)net_read16be(in + 5) << 32) | net_read32be(in + 7);
    (void)on_fragments(d, p, n, 0, seq, t->rx_cap);
  } else if (in[0] == TLS_CT_ALERT && n == 2 && !(t->flags & F_RPROT)) {
    alert_received(d, p[1]); /* before the peer's keys: as TLS */
  } /* an ACK must be protected to be believed */
  return PLAIN_HDR + n;
}

/* One DTLSCiphertext record: the bytes it takes, or 0 */
static size_t on_ciphertext(dtls_conn_t *d, const uint8_t *in, size_t avail) {
  tls_conn_t *t = &d->tls;
  dtls_rec_t h;
  dtls_keys_t *k;
  uint16_t epoch;
  uint64_t seq;
  uint8_t type, *out;
  size_t used;
  int n;
  if (dtls_record_parse(in, avail, &h) != 0)
    return 0;
  used = (size_t)h.hlen + h.len;
  if (!(t->flags & F_RPROT))
    return used; /* no keys yet */
  if ((d->repoch & 3u) == h.epoch) {
    k = &d->r;
    epoch = d->repoch;
  } else if (d->repoch >= 3 && ((d->repoch - 1u) & 3u) == h.epoch) {
    k = &d->r_prev;
    epoch = (uint16_t)(d->repoch - 1);
  } else {
    return used; /* no keys for its epoch */
  }
  if (h.len > (size_t)(t->rx_cap - t->rx_len))
    return used;                   /* no room to open it */
  out = t->rx + t->rx_cap - h.len; /* at the end: scratch */
  if ((n = dtls_record_open(crypto(d), k, in, &h, out, &type, &seq)) < 0) {
    if (++d->bad_records == 0xFFFFFFFFu) /* §4.5.3 */
      (void)tls_fail(t, TLS_ALERT_BAD_RECORD_MAC);
    return used;
  }
  switch (type) {
  case TLS_CT_HANDSHAKE:
    if (n)
      (void)on_fragments(d, out, (size_t)n, epoch, seq, (size_t)(out - t->rx));
    break;
  case TLS_CT_ALERT:
    if (n == 2)
      alert_received(d, out[1]);
    break;
  case TLS_CT_APPLICATION_DATA: /* §5.8.1: only once the handshake is done */
    if (n && t->state == TLS_STATE_CONNECTED) {
      memmove(t->rx + t->rx_len + 2, out, (size_t)n);
      net_write16be(t->rx + t->rx_len, (uint16_t)n);
      t->rx_len = (uint16_t)(t->rx_len + 2 + n);
    }
    break;
  case DTLS_CT_ACK:
    on_ack(d, out, (size_t)n);
    break;
  default: /* authentic, so the peer's doing */
    (void)tls_fail(t, TLS_ALERT_UNEXPECTED_MESSAGE);
  }
  return used;
}

/* ── The API ── */

static void attach(dtls_conn_t *d, const tls_config_t *cfg, uint8_t *rx,
                   size_t rx_cap, uint8_t *tx, size_t tx_cap, size_t mtu) {
  tls_conn_t *t = &d->tls;
  t->cfg = cfg;
  t->rl = &dtls_rl;
  t->rx = rx;
  t->rx_cap = (uint16_t)(rx_cap > BUF_MAX ? BUF_MAX : rx_cap);
  t->tx = tx;
  t->tx_cap = (uint16_t)(tx_cap > BUF_MAX ? BUF_MAX : tx_cap);
  d->mtu = (uint16_t)(mtu > 0xFFFFu ? 0xFFFFu : mtu);
  d->fl_split = NO_SPLIT;
  d->rto_ms = DTLS_RTO_INITIAL_MS;
}

int dtls_init(dtls_conn_t *d, const tls_config_t *cfg, uint8_t *rx,
              size_t rx_cap, uint8_t *tx, size_t tx_cap, size_t mtu) {
  if (!d || !cfg || !cfg->crypto || !cfg->crypto->aes_block || !rx || !tx ||
      rx_cap < BUF_MIN || tx_cap < BUF_MIN || mtu < DTLS_MTU_MIN)
    return -1;
  memset(d, 0, sizeof(*d));
  attach(d, cfg, rx, rx_cap, tx, tx_cap, mtu);
  return 0;
}

int dtls_connect(dtls_conn_t *d, const char *host) {
  if (tls_connect(&d->tls, host) != 0)
    return -1;
  return pump(d) < 0 ? -1 : 0;
}

int dtls_input(dtls_conn_t *d, const uint8_t *dgram, size_t len) {
  tls_conn_t *t = &d->tls;
  size_t off = 0;
  while (off < len &&
         (t->state == TLS_STATE_HANDSHAKE || t->state == TLS_STATE_CONNECTED)) {
    const uint8_t *in = dgram + off;
    size_t used = in[0] == TLS_CT_HANDSHAKE || in[0] == TLS_CT_ALERT ||
                          in[0] == DTLS_CT_ACK
                      ? on_plaintext(d, in, len - off)
                      : on_ciphertext(d, in, len - off);
    if (!used)
      break; /* the rest of the datagram cannot be read */
    off += used;
  }
  if (t->state == TLS_STATE_ERROR)
    return -(int)t->alert;
  if (t->state != TLS_STATE_HANDSHAKE && t->state != TLS_STATE_CONNECTED)
    return 0;
  return pump(d);
}

size_t dtls_pending(dtls_conn_t *d, const uint8_t **dgram) {
  tls_conn_t *t = &d->tls;
  if (!d->dg_len &&
      (t->state == TLS_STATE_HANDSHAKE || t->state == TLS_STATE_CONNECTED ||
       t->state == TLS_STATE_CLOSED))
    build_datagram(d);
  *dgram = t->tx + t->tx_len;
  return d->dg_len;
}

void dtls_sent(dtls_conn_t *d) {
  tls_conn_t *t = &d->tls;
  d->dg_len = 0;
  if (t->state == TLS_STATE_HANDSHAKE || t->state == TLS_STATE_CONNECTED ||
      t->state == TLS_STATE_CLOSED)
    (void)pump(d);
}

void dtls_tick(dtls_conn_t *d, uint32_t elapsed_ms) {
  if (d->fl_state != FL_WAITING || !d->timer_ms)
    return;
  if (elapsed_ms < d->timer_ms) {
    d->timer_ms -= elapsed_ms;
    return;
  }
  if (d->retries >= DTLS_MAX_RETRANSMITS) {
    timed_out(d);
    return;
  }
  d->retries++;
  d->rto_ms = d->rto_ms > DTLS_RTO_MAX_MS / 2 ? DTLS_RTO_MAX_MS : d->rto_ms * 2;
  transmit(d, 1);
}

size_t dtls_max_data(const dtls_conn_t *d) {
  const tls_conn_t *t = &d->tls;
  size_t room = (size_t)(t->tx_cap - t->tx_len);
  size_t limit = t->max_frag ? t->max_frag : TLS_MAX_PLAINTEXT;
  if (room > d->mtu)
    room = d->mtu;
  room = room > DTLS_RECORD_OVERHEAD ? room - DTLS_RECORD_OVERHEAD : 0;
  return room < limit ? room : limit;
}

int dtls_write(dtls_conn_t *d, const uint8_t *data, size_t len) {
  tls_conn_t *t = &d->tls;
  uint8_t *rec;
  if (!writable(t) || len > dtls_max_data(d))
    return -1;
  /* RFC 8446 §5.5's record limit: a KeyUpdate, while these keys go on
   * until it is acknowledged */
  if (d->w.k.seq >= TLS_KEY_UPDATE_RECORDS && !(t->flags & F_KU_SENT)) {
    t->flags |= F_KU_OWED;
    (void)pump(d);
  }
  if (d->dg_len)
    return 0;
  rec = t->tx + t->tx_len;
  memcpy(rec + DTLS_RECORD_HDR, data, len);
  d->dg_len = (uint16_t)dtls_record_seal(crypto(d), &d->w, d->wepoch,
                                         TLS_CT_APPLICATION_DATA, rec, len);
  return (int)len;
}

size_t dtls_read(dtls_conn_t *d, uint8_t *buf, size_t len) {
  tls_conn_t *t = &d->tls;
  uint8_t *e = t->rx + t->hs_len;
  size_t n;
  if (t->rx_len == t->hs_len)
    return 0;
  n = net_read16be(e);
  if (len > n)
    len = n;
  memcpy(buf, e + 2, len);
  if (len == n) { /* the record is used up */
    memmove(e, e + 2 + n, (size_t)(t->rx_len - t->hs_len) - 2 - n);
    t->rx_len = (uint16_t)(t->rx_len - 2 - n);
  } else {
    memmove(e + 2, e + 2 + len, (size_t)(t->rx_len - t->hs_len) - 2 - len);
    net_write16be(e, (uint16_t)(n - len));
    t->rx_len = (uint16_t)(t->rx_len - len);
  }
  return len;
}

int dtls_key_update(dtls_conn_t *d, int request) {
  tls_conn_t *t = &d->tls;
  if (!writable(t))
    return -1;
  t->flags |= F_KU_OWED | (request ? F_KU_REQ : 0u);
  (void)pump(d);
  return 0;
}

int dtls_close(dtls_conn_t *d) {
  tls_conn_t *t = &d->tls;
  if (t->flags & F_WCLOSED)
    return 0;
  if (t->state == TLS_STATE_IDLE || t->state == TLS_STATE_ERROR ||
      queue_alert(d, ALERT_WARNING, TLS_ALERT_CLOSE_NOTIFY) != 0)
    return -1;
  t->flags |= F_WCLOSED;
  tls_wipe_keys_if_closed(t);
  return 0;
}

void dtls_release(dtls_conn_t *d) {
  tls_conn_t *t = &d->tls;
  const tls_config_t *cfg = t->cfg;
  uint8_t *rx = t->rx, *tx = t->tx;
  uint16_t rx_cap = t->rx_cap, tx_cap = t->tx_cap, mtu = d->mtu;
  void (*on_event)(tls_conn_t *, uint8_t) = t->on_event;
  void *user = t->user;
  if (rx)
    tls_wipe(rx, rx_cap);
  if (tx)
    tls_wipe(tx, tx_cap);
  tls_wipe(d, sizeof(*d));
  attach(d, cfg, rx, rx_cap, tx, tx_cap, mtu);
  t->on_event = on_event;
  t->user = user;
}

int dtls_peer_verified(const dtls_conn_t *d) {
  const tls_conn_t *t = &d->tls;
  return (t->flags & F_VERIFIED) || t->state == TLS_STATE_CONNECTED ||
         t->state == TLS_STATE_CLOSED;
}
