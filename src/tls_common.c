/**
 * @file tls_common.c
 * @brief What the TLS stream record layer (tls.c) and the DTLS datagram
 *        record layer (dtls.c) share with the handshake of each role:
 *        handshake message framing, installing traffic keys, the messages
 *        that follow the handshake, alerts received, failing.
 *
 * The record layer is reached only through tls_conn_t.rl, so a build
 * links only the record layers it starts connections on.
 *
 * No division: this builds for Cortex-M0.
 */

#include "tls_internal.h"

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

void tls_wipe_keys(tls_conn_t *t) {
  tls_wipe(t->secret, sizeof(t->secret));
  tls_wipe(t->rsec, sizeof(t->rsec));
  tls_wipe(t->wsec, sizeof(t->wsec));
  tls_wipe(&t->rkeys, sizeof(t->rkeys));
  tls_wipe(&t->wkeys, sizeof(t->wkeys));
  tls_wipe(t->kx_priv, sizeof(t->kx_priv));
  if (t->rl->wipe)
    t->rl->wipe(t);
}

void tls_wipe_keys_if_closed(tls_conn_t *t) {
  if (t->state == TLS_STATE_CLOSED && (t->flags & F_WCLOSED))
    tls_wipe_keys(t);
}

/* ── Reading hellos ── */

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

/* ── Writing handshake messages, through the record layer ── */

uint8_t *tls_hs_begin(tls_conn_t *t, size_t max) {
  return t->rl->hs_begin(t, max);
}

/* The transcript takes the TLS form of the message under DTLS too (RFC
 * 9147 §5.2): the record layer adds the DTLS fields when it sends it */
void tls_hs_end(tls_conn_t *t, uint8_t *m, uint8_t type, size_t body) {
  m[0] = type;
  net_write24be(m + 1, (uint32_t)body);
  t->cfg->crypto->hash_update(&t->transcript, m, HS_HDR + body);
  t->tx_len = (uint16_t)(t->tx_len + HS_HDR + body);
}

void tls_hs_flush(tls_conn_t *t) { t->rl->hs_flush(t); }

int tls_queue_ccs(tls_conn_t *t) { return t->rl->ccs(t); }

void tls_set_keys(tls_conn_t *t, int write) { t->rl->set_keys(t, write); }

int tls_fail(tls_conn_t *t, int alert) {
  t->rl->alert(t, ALERT_FATAL, (uint8_t)alert); /* if there is room */
  t->state = TLS_STATE_ERROR;
  t->alert = (uint8_t)alert;
  tls_wipe_keys(t);
  tls_notify(t, TLS_EVT_ERROR);
  return -alert;
}

/* ── After the handshake ── */

/* RFC 8446 §4.6.3: the peer's next keys; answer if asked.  Its sending
 * keys have now changed, which is all a request of ours still waiting to
 * go would ask for: ours no longer asks. */
static int on_key_update(tls_conn_t *t, const uint8_t *m, size_t mlen) {
  if (mlen != HS_HDR + 1)
    return tls_fail(t, TLS_ALERT_DECODE_ERROR);
  if (m[HS_HDR] > 1)
    return tls_fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
  tls_update_secret(t->cfg->crypto, tls_is_dtls(t), t->rsec);
  tls_set_keys(t, 0);
  t->flags &= (uint16_t)~F_KU_REQ;
  if (m[HS_HDR])
    t->flags |= F_KU_OWED | F_KU_ANS;
  return HS_KEYS;
}

int tls_on_handshake(tls_conn_t *t, const uint8_t *m, size_t mlen) {
  if (t->state != TLS_STATE_CONNECTED)
    return t->role->on_message(t, m, mlen);
  if (m[0] == TLS_HS_KEY_UPDATE)
    return on_key_update(t, m, mlen);
  /* tickets are for resumption, which a client here does not do */
  if (m[0] == TLS_HS_NEW_SESSION_TICKET && !(t->flags & F_SERVER))
    return 0;
  return tls_fail(t, TLS_ALERT_UNEXPECTED_MESSAGE);
}

int tls_alert_received(tls_conn_t *t, uint8_t desc) {
  if (desc == TLS_ALERT_USER_CANCELED) /* close_notify follows */
    return 0;
  if (desc == TLS_ALERT_CLOSE_NOTIFY) {
    t->state = TLS_STATE_CLOSED;
    tls_wipe_keys_if_closed(t);
    tls_notify(t, TLS_EVT_CLOSED);
    return 0;
  }
  t->state = TLS_STATE_ERROR;
  t->alert = desc;
  tls_wipe_keys(t);
  tls_notify(t, TLS_EVT_ERROR);
  return -(int)desc;
}

int tls_psk_used(const tls_conn_t *t) { return (t->flags & F_PSK) != 0; }
