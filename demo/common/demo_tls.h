/**
 * @file demo_tls.h
 * @brief Shared by the TLS demos: a pre-shared key from the environment.
 *
 *   TLS_PSK        the key, hex (e.g. 32 bytes = 64 hex digits)
 *   TLS_PSK_ID     its identity                     (default "device-1")
 *   TLS_PSK_MODES  "dhe" (psk_dhe_ke, the default), "ke" (psk_ke) or
 *                  "both"
 */

#ifndef DEMO_TLS_H
#define DEMO_TLS_H

#include "tls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Fill @p cfg's PSK fields from the environment; 0 if none is set, 1 if
 * one is, -1 if TLS_PSK is not valid hex. */
static inline int demo_tls_psk(tls_config_t *cfg, uint8_t *buf, size_t cap) {
  const char *hex = getenv("TLS_PSK"), *id = getenv("TLS_PSK_ID");
  const char *modes = getenv("TLS_PSK_MODES");
  size_t n = 0;
  if (!hex || !*hex)
    return 0;
  while (hex[0] && hex[1] && n < cap) {
    unsigned v;
    if (sscanf(hex, "%2x", &v) != 1)
      return -1;
    buf[n++] = (uint8_t)v;
    hex += 2;
  }
  if (*hex || n == 0)
    return -1;
  if (!id || !*id)
    id = "device-1";
  cfg->psk = buf;
  cfg->psk_len = (uint16_t)n;
  cfg->psk_id = (const uint8_t *)id;
  cfg->psk_id_len = (uint16_t)strlen(id);
  cfg->psk_modes = TLS_PSK_DHE_KE;
  if (modes && strcmp(modes, "ke") == 0)
    cfg->psk_modes = TLS_PSK_KE;
  else if (modes && strcmp(modes, "both") == 0)
    cfg->psk_modes = TLS_PSK_KE | TLS_PSK_DHE_KE;
  return 1;
}

#endif /* DEMO_TLS_H */
