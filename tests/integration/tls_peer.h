/**
 * @file tls_peer.h
 * @brief The peer of the TLS 1.3 and DTLS 1.3 integration tests: a
 *        pre-shared-key client and server written from RFC 8446 and RFC
 *        9147 — its own HKDF labels, key schedule, hellos, Finished and
 *        record protection, on Mbed TLS's SHA-256, AES and X25519.
 *
 * Nothing here calls the stack's TLS code, so what the stack sends is
 * checked against the RFCs and not against itself.
 */

#ifndef TLS_PEER_H
#define TLS_PEER_H

#include <stddef.h>
#include <stdint.h>

/* ContentType, HandshakeType, ExtensionType, alerts: the RFCs' numbers */
#define TP_CCS 20
#define TP_ALERT 21
#define TP_HANDSHAKE 22
#define TP_APPDATA 23
#define TP_ACK 26

#define TP_CLIENT_HELLO 1
#define TP_SERVER_HELLO 2
#define TP_NEW_SESSION_TICKET 4
#define TP_ENCRYPTED_EXTENSIONS 8
#define TP_CERTIFICATE 11
#define TP_CERTIFICATE_REQUEST 13
#define TP_FINISHED 20
#define TP_KEY_UPDATE 24

#define TP_EXT_SERVER_NAME 0
#define TP_EXT_MAX_FRAGMENT_LENGTH 1
#define TP_EXT_SUPPORTED_GROUPS 10
#define TP_EXT_SIGNATURE_ALGORITHMS 13
#define TP_EXT_PRE_SHARED_KEY 41
#define TP_EXT_SUPPORTED_VERSIONS 43
#define TP_EXT_COOKIE 44
#define TP_EXT_PSK_MODES 45
#define TP_EXT_KEY_SHARE 51

#define TP_SUITE 0x1301 /* TLS_AES_128_GCM_SHA256 */
#define TP_X25519 0x001D
#define TP_P256 0x0017

/** ServerHello.random of a HelloRetryRequest (RFC 8446 §4.1.3) */
extern const uint8_t tp_hrr_random[32];

/* Big-endian fields of @p n bytes */
uint32_t tp_get(const uint8_t *p, int n);
void tp_put(uint8_t *p, int n, uint32_t v);

/* ── Primitives ── */

void tp_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void tp_hmac(const uint8_t *key, size_t key_len, const uint8_t *data,
             size_t len, uint8_t out[32]);
/** HKDF-Expand-Label (RFC 8446 §7.1) under "tls13 ", or "dtls13" (RFC 9147
 *  §5.9) for @p dtls; at most 32 bytes. */
void tp_expand_label(int dtls, const uint8_t secret[32], const char *label,
                     const uint8_t *context, size_t context_len, uint8_t *out,
                     size_t out_len);
void tp_x25519_keygen(uint8_t priv[32], uint8_t pub[32]);
/** 0, or -1 if @p peer is no usable share */
int tp_x25519(const uint8_t priv[32], const uint8_t peer[32],
              uint8_t shared[32]);

/* ── Records ── */

typedef struct {
  uint8_t key[16], iv[12];
  uint8_t sn[16]; /* DTLS: the record number key */
  uint64_t seq;   /* records sealed, or opened, so far */
} tp_keys_t;

/** [sender]_write_key and _iv of @p secret (RFC 8446 §7.3), and DTLS's
 *  sn_key (RFC 9147 §4.2.3); sequence 0 */
void tp_traffic_keys(int dtls, const uint8_t secret[32], tp_keys_t *k);

/** A TLSPlaintext record; its length */
size_t tp_record(uint8_t type, const uint8_t *content, size_t n, uint8_t *rec);
/** A TLSCiphertext record (RFC 8446 §5.2) with @p pad zero bytes of
 *  padding; its length */
size_t tp_seal(tp_keys_t *k, uint8_t type, const uint8_t *content, size_t n,
               size_t pad, uint8_t *rec);
/** Open the TLSCiphertext record at @p rec: the content length (its type
 *  in @p type), or -1 if it does not authenticate */
int tp_open(tp_keys_t *k, const uint8_t *rec, size_t rec_len, uint8_t *content,
            uint8_t *type);

/** A DTLSPlaintext record of epoch 0, record number @p seq */
size_t tp_drecord(uint8_t type, uint64_t seq, const uint8_t *content, size_t n,
                  uint8_t *rec);
/** A DTLSCiphertext record (RFC 9147 §4) of @p epoch: a 16-bit sequence
 *  number and a length (@p short_hdr: an 8-bit one and no length) */
size_t tp_dseal(tp_keys_t *k, unsigned epoch, uint8_t type,
                const uint8_t *content, size_t n, int short_hdr, uint8_t *rec);
/** A DTLSCiphertext record as the stack sends it (001 C=0 S=1 L=1) */
typedef struct {
  unsigned epoch_bits;
  uint16_t seq;   /* as unmasked */
  size_t rec_len; /* the whole record */
} tp_drec_t;
/** Open the DTLSCiphertext record at @p rec (@p avail bytes left in the
 *  datagram): the content length, -1 if it is not such a record or does
 *  not authenticate under @p k */
int tp_dopen(const tp_keys_t *k, const uint8_t *rec, size_t avail,
             uint8_t *content, uint8_t *type, tp_drec_t *info);

/* ── The handshake ── */

#define TP_TRANSCRIPT_MAX 8192

typedef struct {
  int dtls;
  const uint8_t *psk;
  size_t psk_len;
  const char *psk_id;
  uint8_t random[32];
  uint8_t x_priv[32], x_pub[32];
  /* Every handshake message so far, in TLS form */
  uint8_t transcript[TP_TRANSCRIPT_MAX];
  size_t transcript_len;
  uint8_t early[32], handshake[32], master[32];
  uint8_t c_hs[32], s_hs[32], c_ap[32], s_ap[32];
} tp_t;

void tp_init(tp_t *p, int dtls, const uint8_t *psk, size_t psk_len,
             const char *psk_id);
void tp_add(tp_t *p, const uint8_t *msg, size_t len);
void tp_transcript_hash(const tp_t *p, uint8_t out[32]);
/** After a HelloRetryRequest: ClientHello1 gives way to message_hash */
void tp_message_hash(tp_t *p);

/** What a ClientHello of the peer carries, besides what every one does:
 *  a cipher suite, an extension and a version that no server knows (they
 *  must be ignored), then TLS_AES_128_GCM_SHA256 and the real version */
typedef struct {
  const uint8_t *session_id; /* TLS compatibility mode */
  size_t session_id_len;
  const uint8_t *legacy_cookie; /* DTLS; normally empty */
  size_t legacy_cookie_len;
  uint16_t version; /* in supported_versions; 0: this protocol's 1.3 */
  int no_versions;
  int psk_ke, psk_dhe; /* psk_key_exchange_modes offered */
  int no_psk, no_modes, bad_binder;
  int share;             /* supported_groups and an x25519 key_share */
  int groups_no_share;   /* supported_groups (P-256, x25519), no shares */
  int sig_algs;          /* signature_algorithms */
  const uint8_t *cookie; /* the cookie extension */
  size_t cookie_len;
  uint8_t mfl;         /* max_fragment_length code */
  uint8_t compression; /* legacy_compression_methods' one method */
  int no_suite;        /* TLS_AES_128_GCM_SHA256 not among the suites */
  int psk_not_last;    /* an extension after pre_shared_key */
  int truncated;       /* the message ends before its extensions do */
  int zero_share;      /* the x25519 share is 32 zero bytes */
  int groups_only;     /* supported_groups without a key_share extension */
  int early_data;      /* the early_data extension */
  int twice;           /* supported_versions a second time */
} tp_ch_t;

/** The ClientHello (handshake header included), added to the transcript;
 *  its length */
size_t tp_client_hello(tp_t *p, const tp_ch_t *o, uint8_t *msg);

/** A hello, read */
typedef struct {
  uint16_t legacy_version;
  const uint8_t *random;
  const uint8_t *session_id;
  size_t session_id_len;
  const uint8_t *legacy_cookie; /* a DTLS ClientHello's */
  size_t legacy_cookie_len;
  const uint8_t *suites; /* a ClientHello's list */
  size_t suites_len;
  uint16_t suite; /* a ServerHello's choice */
  const uint8_t *compression;
  size_t compression_len;
  const uint8_t *exts;
  size_t exts_len;
} tp_hello_t;

/** Read the ClientHello or ServerHello message @p msg: 1 if well formed */
int tp_parse_hello(const uint8_t *msg, size_t len, int dtls, tp_hello_t *h);
/** Extension @p type of the hello: its data (and length), NULL if absent */
const uint8_t *tp_ext(const tp_hello_t *h, uint16_t type, size_t *len);
/** How many extensions the hello has, and the type of the last */
int tp_ext_count(const tp_hello_t *h, uint16_t *last);
/** 1 if the binder of the ClientHello @p msg (which the transcript does
 *  not hold yet) is the one RFC 8446 §4.2.11.2 defines for the peer's PSK */
int tp_binder_ok(tp_t *p, const uint8_t *msg, size_t len);

/** What a ServerHello (or HelloRetryRequest) of the peer carries */
typedef struct {
  int hrr;
  uint16_t version; /* 0: this protocol's 1.3 */
  int no_versions;
  const uint8_t *session_id; /* echoed */
  size_t session_id_len;
  int psk;   /* pre_shared_key: identity 0 */
  int share; /* key_share: our x25519 share */
  uint16_t hrr_group;
  const uint8_t *cookie;
  size_t cookie_len;
  int stray; /* an extension that does not belong: its type + 1 */
  uint16_t suite;       /* 0: TLS_AES_128_GCM_SHA256 */
  uint16_t share_group; /* 0: x25519 */
  int zero_share;       /* the share is 32 zero bytes */
  int truncated;        /* the message ends before its extensions do */
  uint8_t compression;  /* legacy_compression_method */
} tp_sh_t;

/** The ServerHello, added to the transcript; its length */
size_t tp_server_hello(tp_t *p, const tp_sh_t *o, uint8_t *msg);
/** EncryptedExtensions with no extension (or the one of @p type, @p len
 *  bytes of @p data), added to the transcript */
size_t tp_encrypted_extensions(tp_t *p, int type, const uint8_t *data,
                               size_t len, uint8_t *msg);
/** CertificateRequest with an empty context and signature_algorithms,
 *  added to the transcript */
size_t tp_certificate_request(tp_t *p, uint8_t *msg);
/** Certificate with the @p n DER certificates (and @p context bytes of
 *  certificate_request_context), added to the transcript */
size_t tp_certificate(tp_t *p, const uint8_t *const *der, const uint16_t *len,
                      int n, int context, uint8_t *msg);
/** CertificateVerify by a server: @p scheme, and the ECDSA P-256 / SHA-256
 *  signature by the PEM private key @p key of the content RFC 8446 §4.4.3
 *  defines over the transcript so far; added to the transcript.  0 if the
 *  key could not sign. */
size_t tp_certificate_verify(tp_t *p, uint16_t scheme, const char *key,
                             size_t key_len, uint8_t *msg);
/** Finished under traffic secret @p base over the transcript so far,
 *  added to the transcript; its length (36) */
size_t tp_finished(tp_t *p, const uint8_t base[32], uint8_t *msg);
/** The verify_data a Finished under @p base must carry now */
void tp_verify_data(const tp_t *p, const uint8_t base[32], uint8_t out[32]);

/** The Early Secret, from the PSK (or from zeros when @p with_psk is 0) */
void tp_early_secret(tp_t *p, int with_psk);
/** Handshake Secret and both handshake traffic secrets, the transcript
 *  holding ClientHello .. ServerHello; @p dhe NULL for psk_ke */
void tp_handshake_secrets(tp_t *p, const uint8_t *dhe);
/** Master Secret and both application traffic secrets, the transcript
 *  holding ClientHello .. server Finished */
void tp_application_secrets(tp_t *p);
/** The next generation of a traffic secret (RFC 8446 §7.2) */
void tp_update_secret(int dtls, uint8_t secret[32]);

/* ── DTLS handshake messages (RFC 9147 §5.2) ── */

/** A fragment — bytes [@p off, @p off + @p n) of the body — of the
 *  TLS-form message @p msg as message @p mseq; its length (12 + n) */
size_t tp_dfragment(const uint8_t *msg, uint16_t mseq, size_t off, size_t n,
                    uint8_t *out);

/** Reassembly of the stack's handshake messages, which arrive in order */
typedef struct {
  uint8_t msg[4096]; /* the message being put together, in TLS form */
  size_t have, len;  /* body bytes so far, and in all */
  uint16_t next_seq; /* message_seq expected */
  int overlaps;      /* fragments that overlapped what was there */
  int bad;           /* out of order, or inconsistent */
} tp_reasm_t;

/** Take the handshake fragment at @p f (@p avail bytes left in its record):
 *  the bytes it used (0 if malformed).  When it completes the message,
 *  @p *done is the message's TLS-form length, and the next call starts the
 *  next message. */
size_t tp_reassemble(tp_reasm_t *r, const uint8_t *f, size_t avail,
                     size_t *done);

#endif /* TLS_PEER_H */
