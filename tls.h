/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Minimal TLS 1.3 client for kwebdavfs
 *
 * Implements TLS 1.3 (RFC 8446) using kernel crypto APIs:
 *   - x25519 ECDHE key exchange  (crypto/curve25519.h)
 *   - HMAC-SHA256 / HKDF         (crypto/hash.h)
 *   - AES-128-GCM                (crypto/aead.h)
 *
 * Certificate verification is skipped (like curl -k) since the kernel
 * has no CA store.  The channel is still fully encrypted.
 */

#ifndef _KWEBDAVFS_TLS_H
#define _KWEBDAVFS_TLS_H

#include <linux/types.h>
#include <linux/net.h>

struct tls13_ctx;

/**
 * tls13_connect - perform TLS 1.3 handshake on an already-connected socket
 * @sock:     TCP socket (connected to server)
 * @hostname: server hostname (used for SNI)
 * @out:      on success, set to a newly allocated tls13_ctx
 *
 * Returns 0 on success, negative errno otherwise.
 */
int tls13_connect(struct socket *sock, const char *hostname,
                  struct tls13_ctx **out);

/**
 * tls13_send - encrypt and send plaintext application data
 * @ctx:  TLS context from tls13_connect()
 * @data: plaintext buffer
 * @len:  number of bytes to send
 *
 * Returns bytes sent on success, negative errno otherwise.
 */
int tls13_send(struct tls13_ctx *ctx, const void *data, size_t len);

/**
 * tls13_recv - receive and decrypt application data
 * @ctx:   TLS context
 * @buf:   destination buffer
 * @len:   max bytes to read
 * @flags: MSG_WAITALL etc.
 *
 * Returns bytes received on success, 0 on EOF, negative errno on error.
 */
int tls13_recv(struct tls13_ctx *ctx, void *buf, size_t len, int flags);

/**
 * tls13_free - release a TLS context (does NOT close the socket)
 */
void tls13_free(struct tls13_ctx *ctx);

#endif /* _KWEBDAVFS_TLS_H */
