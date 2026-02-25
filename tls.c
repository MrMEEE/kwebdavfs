// SPDX-License-Identifier: GPL-2.0
/*
 * Minimal TLS 1.3 client for kwebdavfs
 *
 * Cipher suite : TLS_AES_128_GCM_SHA256  (0x1301)
 * Key exchange : x25519  (curve25519 kernel library)
 * AEAD         : AES-128-GCM  (kernel crypto "gcm(aes)")
 * PRF / KDF    : HKDF-SHA-256 (kernel crypto hkdf.h + hmac(sha256))
 *
 * Certificate verification is intentionally skipped; the channel is
 * still fully encrypted (like curl --insecure).
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/sched/signal.h>
#include <linux/scatterlist.h>
#include <net/sock.h>
#include <crypto/ecdh.h>
#include <crypto/kpp.h>
#include <crypto/hkdf.h>
#include <crypto/hash.h>
#include <crypto/aead.h>
#include <linux/unaligned.h>

#include "tls.h"

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */
#define TLS_CIPHER_AES128_GCM_SHA256   0x1301

#define TLS_CONTENT_CCS         20
#define TLS_CONTENT_ALERT       21
#define TLS_CONTENT_HANDSHAKE   22
#define TLS_CONTENT_APPDATA     23

#define TLS_HS_CLIENT_HELLO      1
#define TLS_HS_SERVER_HELLO      2
#define TLS_HS_ENCRYPTED_EXTS    8
#define TLS_HS_CERTIFICATE      11
#define TLS_HS_CERT_VERIFY      15
#define TLS_HS_FINISHED         20

#define TLS_EXT_SERVER_NAME         0x0000
#define TLS_EXT_SUPPORTED_GROUPS    0x000a
#define TLS_EXT_SIG_ALGS            0x000d
#define TLS_EXT_SUPPORTED_VERSIONS  0x002b
#define TLS_EXT_KEY_SHARE           0x0033

#define TLS_GROUP_P256          0x0017   /* secp256r1 */

/* P-256 sizes */
#define P256_PRIV_LEN        32
#define P256_PUB_RAW_LEN     64   /* x||y (kernel KPP format) */
#define P256_PUB_WIRE_LEN    65   /* 0x04 || x || y (TLS wire format) */
#define P256_SHARED_LEN      32   /* x-coordinate of shared point */

#define AES128GCM_KEY_LEN   16
#define AES128GCM_IV_LEN    12
#define AES128GCM_TAG_LEN   16
#define SHA256_LEN          32

/* ------------------------------------------------------------------ */
/*  Internal context                                                   */
/* ------------------------------------------------------------------ */
struct tls13_ctx {
    struct socket *sock;

    /* Handshake KPP context (freed after handshake) */
    struct crypto_kpp *kpp;

    /* HKDF secrets */
    u8  handshake_secret[SHA256_LEN];
    u8  client_hs_secret[SHA256_LEN];
    u8  server_hs_secret[SHA256_LEN];

    /* Handshake traffic keys */
    u8  c_hs_key[AES128GCM_KEY_LEN];
    u8  c_hs_iv [AES128GCM_IV_LEN];
    u8  s_hs_key[AES128GCM_KEY_LEN];
    u8  s_hs_iv [AES128GCM_IV_LEN];

    /* Application traffic keys */
    u8  c_app_key[AES128GCM_KEY_LEN];
    u8  c_app_iv [AES128GCM_IV_LEN];
    u8  s_app_key[AES128GCM_KEY_LEN];
    u8  s_app_iv [AES128GCM_IV_LEN];

    /* Per-direction sequence numbers */
    u64 c_hs_seq, s_hs_seq;
    u64 c_app_seq, s_app_seq;

    bool handshake_done;

    /* Running transcript (all Handshake message bytes) */
    u8   *transcript;
    size_t tscript_len;

    /* Crypto transforms */
    struct crypto_shash *sha256;
    struct crypto_shash *hmac_sha256;
};

/* ------------------------------------------------------------------ */
/*  P-256 ECDH helpers (KPP framework)                                */
/* ------------------------------------------------------------------ */

/*
 * Generate a P-256 ephemeral key pair.
 * Returns an allocated crypto_kpp that must be kept for shared-secret step.
 * pub_wire: 65-byte output (0x04 || x || y) for TLS key_share.
 */
static struct crypto_kpp *p256_gen_keypair(u8 pub_wire[P256_PUB_WIRE_LEN])
{
    struct crypto_kpp   *tfm;
    struct kpp_request  *req;
    struct scatterlist   dst_sg;
    struct crypto_wait   cw;
    u8   priv_raw[P256_PRIV_LEN];
    u8   pub_raw[P256_PUB_RAW_LEN];
    struct ecdh params  = { .key = (char *)priv_raw, .key_size = P256_PRIV_LEN };
    unsigned int klen;
    u8  *kbuf = NULL;
    int  ret;

    get_random_bytes(priv_raw, P256_PRIV_LEN);

    tfm = crypto_alloc_kpp("ecdh-nist-p256", 0, 0);
    if (IS_ERR(tfm)) return tfm;

    klen = crypto_ecdh_key_len(&params);
    kbuf = kmalloc(klen, GFP_KERNEL);
    if (!kbuf) { ret = -ENOMEM; goto err; }

    ret = crypto_ecdh_encode_key(kbuf, klen, &params);
    if (ret) goto err;
    ret = crypto_kpp_set_secret(tfm, kbuf, klen);
    kfree(kbuf); kbuf = NULL;
    if (ret) goto err;

    req = kpp_request_alloc(tfm, GFP_KERNEL);
    if (!req) { ret = -ENOMEM; goto err; }

    sg_init_one(&dst_sg, pub_raw, P256_PUB_RAW_LEN);
    kpp_request_set_input(req, NULL, 0);
    kpp_request_set_output(req, &dst_sg, P256_PUB_RAW_LEN);
    crypto_init_wait(&cw);
    kpp_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                             crypto_req_done, &cw);
    ret = crypto_wait_req(crypto_kpp_generate_public_key(req), &cw);
    kpp_request_free(req);
    if (ret) goto err;

    /* Convert raw x||y to uncompressed wire format: 0x04 || x || y */
    pub_wire[0] = 0x04;
    memcpy(pub_wire + 1, pub_raw, P256_PUB_RAW_LEN);

    memzero_explicit(priv_raw, sizeof(priv_raw));
    return tfm;
err:
    kfree(kbuf);
    memzero_explicit(priv_raw, sizeof(priv_raw));
    crypto_free_kpp(tfm);
    return ERR_PTR(ret);
}

/*
 * Compute ECDH shared secret.
 * peer_wire: 65-byte server public key (0x04 || x || y)
 * shared:    32-byte output (x-coordinate of shared point)
 * kpp handle from p256_gen_keypair must still be valid.
 */
static int p256_shared_secret(struct crypto_kpp *tfm,
                               const u8 peer_wire[P256_PUB_WIRE_LEN],
                               u8 shared[P256_SHARED_LEN])
{
    struct kpp_request *req;
    struct scatterlist  src_sg, dst_sg;
    struct crypto_wait  cw;
    u8  peer_raw[P256_PUB_RAW_LEN]; /* x||y without 0x04 */
    int ret;

    if (peer_wire[0] != 0x04) return -EINVAL; /* only uncompressed */
    memcpy(peer_raw, peer_wire + 1, P256_PUB_RAW_LEN);

    req = kpp_request_alloc(tfm, GFP_KERNEL);
    if (!req) return -ENOMEM;

    sg_init_one(&src_sg, peer_raw, P256_PUB_RAW_LEN);
    sg_init_one(&dst_sg, shared,   P256_SHARED_LEN);
    kpp_request_set_input(req, &src_sg, P256_PUB_RAW_LEN);
    kpp_request_set_output(req, &dst_sg, P256_SHARED_LEN);
    crypto_init_wait(&cw);
    kpp_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                             crypto_req_done, &cw);
    ret = crypto_wait_req(crypto_kpp_compute_shared_secret(req), &cw);
    kpp_request_free(req);
    return ret;
}
static int tls_send_all(struct socket *sock, const u8 *data, size_t len)
{
    struct msghdr msg = { .msg_flags = MSG_NOSIGNAL };
    struct kvec   iov;
    size_t sent = 0;
    int ret;

    while (sent < len) {
        iov.iov_base = (void *)(data + sent);
        iov.iov_len  = len - sent;
        ret = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
        if (ret == -ERESTARTSYS) continue; /* kernel restart, retry */
        if (ret == -EINTR) {
            if (fatal_signal_pending(current)) return -EINTR;
            continue; /* non-fatal signal, retry */
        }
        if (ret < 0) return ret;
        if (ret == 0) return -ECONNRESET;
        sent += ret;
    }
    return 0;
}

static int tls_recv_all(struct socket *sock, u8 *data, size_t len)
{
    struct msghdr msg = { .msg_flags = 0 };
    struct kvec   iov;
    size_t recvd = 0;
    int ret;

    while (recvd < len) {
        iov.iov_base = data + recvd;
        iov.iov_len  = len - recvd;
        ret = kernel_recvmsg(sock, &msg, &iov, 1, iov.iov_len, 0);
        if (ret == -ERESTARTSYS) continue; /* kernel restart, retry */
        if (ret == -EINTR) {
            /* Only abort on fatal signals (SIGKILL); retry otherwise */
            if (fatal_signal_pending(current)) return -EINTR;
            continue;
        }
        if (ret == -EAGAIN || ret == -ETIMEDOUT) {
            printk(KERN_ERR "kwebdavfs/tls: socket timeout after %zu/%zu bytes\n",
                   recvd, len);
            return -ETIMEDOUT;
        }
        if (ret < 0) return ret;
        if (ret == 0) {
            /* Peer closed connection — treat as clean EOF if we have data */
            if (recvd > 0) return (int)recvd;
            return -ECONNRESET;
        }
        recvd += ret;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Low-level socket helpers                                           */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/*  Crypto helpers                                                     */
/* ------------------------------------------------------------------ */
static int do_sha256(struct crypto_shash *tfm,
                     const u8 *src, size_t len, u8 out[SHA256_LEN])
{
    static const u8 empty[1] = {0};
    SHASH_DESC_ON_STACK(desc, tfm);
    int ret;
    desc->tfm = tfm;
    ret = crypto_shash_digest(desc, src ? src : empty, src ? len : 0, out);
    shash_desc_zero(desc);
    return ret;
}

/* HMAC-SHA-256 */
static int do_hmac_sha256(struct crypto_shash *tfm,
                          const u8 *key, size_t klen,
                          const u8 *msg, size_t mlen,
                          u8 out[SHA256_LEN])
{
    SHASH_DESC_ON_STACK(desc, tfm);
    int ret;
    ret = crypto_shash_setkey(tfm, key, klen);
    if (ret) return ret;
    desc->tfm = tfm;
    ret = crypto_shash_digest(desc, msg, mlen, out);
    shash_desc_zero(desc);
    return ret;
}

/*
 * HKDF-Expand-Label (RFC 8446 §7.1):
 *   HKDF-Expand-Label(secret, label, context, length)
 *     = HKDF-Expand(secret, HkdfLabel, length)
 *   HkdfLabel = uint16(length) || uint8(len("tls13 "+label))
 *               || "tls13 " || label || uint8(len(context)) || context
 */
static int hkdf_expand_label(struct crypto_shash *hmac_tfm,
                              const u8 *secret, size_t secret_len,
                              const char *label, size_t label_len,
                              const u8 *context, size_t ctx_len,
                              u8 *out, size_t out_len)
{
    /* max info length: 2 + 1 + 6 + 255 + 1 + 32 = 297 */
    u8   info[300];
    size_t pos = 0;
    int ret;

    if (2 + 1 + 6 + label_len + 1 + ctx_len > sizeof(info))
        return -EINVAL;

    info[pos++] = (out_len >> 8) & 0xff;
    info[pos++] =  out_len & 0xff;
    info[pos++] = (u8)(6 + label_len);
    memcpy(&info[pos], "tls13 ", 6); pos += 6;
    memcpy(&info[pos], label, label_len); pos += label_len;
    info[pos++] = (u8)ctx_len;
    if (ctx_len) {
        memcpy(&info[pos], context, ctx_len);
        pos += ctx_len;
    }

    ret = crypto_shash_setkey(hmac_tfm, secret, secret_len);
    if (ret) return ret;
    return hkdf_expand(hmac_tfm, info, pos, out, out_len);
}

/* ------------------------------------------------------------------ */
/*  Transcript management                                              */
/* ------------------------------------------------------------------ */
static int tscript_add(struct tls13_ctx *ctx, const u8 *data, size_t len)
{
    u8 *p = krealloc(ctx->transcript, ctx->tscript_len + len, GFP_KERNEL);
    if (!p) return -ENOMEM;
    ctx->transcript = p;
    memcpy(p + ctx->tscript_len, data, len);
    ctx->tscript_len += len;
    return 0;
}

static int tscript_hash(struct tls13_ctx *ctx, u8 out[SHA256_LEN])
{
    return do_sha256(ctx->sha256, ctx->transcript, ctx->tscript_len, out);
}

/* ------------------------------------------------------------------ */
/*  AES-128-GCM encrypt / decrypt                                     */
/* ------------------------------------------------------------------ */

/* Build TLS 1.3 per-record nonce: iv XOR left-padded seqnum */
static void make_nonce(const u8 iv[AES128GCM_IV_LEN], u64 seq,
                       u8 nonce[AES128GCM_IV_LEN])
{
    int i;
    u8  seq_be[8];
    put_unaligned_be64(seq, seq_be);
    for (i = 0; i < AES128GCM_IV_LEN; i++) {
        u8 s = (i < AES128GCM_IV_LEN - 8) ? 0 : seq_be[i - (AES128GCM_IV_LEN - 8)];
        nonce[i] = iv[i] ^ s;
    }
}

/*
 * Encrypt plaintext -> ciphertext (plain_len + TAG_LEN bytes).
 * aad is used only as additional auth data; its bytes are NOT prepended
 * to the output (caller handles that).
 */
static int aes128gcm_enc(const u8 key[AES128GCM_KEY_LEN],
                         const u8 nonce[AES128GCM_IV_LEN],
                         const u8 *aad, size_t aad_len,
                         const u8 *plain, size_t plain_len,
                         u8 *out /* plain_len + TAG_LEN */)
{
    struct crypto_aead *tfm;
    struct aead_request *req;
    struct scatterlist  sg;
    struct crypto_wait  wait;
    u8  *buf;
    size_t buf_len = aad_len + plain_len + AES128GCM_TAG_LEN;
    int ret;

    tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
    if (IS_ERR(tfm)) return PTR_ERR(tfm);
    ret = crypto_aead_setkey(tfm, key, AES128GCM_KEY_LEN);
    if (ret) goto free_tfm;
    ret = crypto_aead_setauthsize(tfm, AES128GCM_TAG_LEN);
    if (ret) goto free_tfm;

    req = aead_request_alloc(tfm, GFP_KERNEL);
    if (!req) { ret = -ENOMEM; goto free_tfm; }

    buf = kmalloc(buf_len, GFP_KERNEL);
    if (!buf) { ret = -ENOMEM; goto free_req; }

    /* Layout: [aad | plaintext | tag_space] */
    memcpy(buf, aad, aad_len);
    memcpy(buf + aad_len, plain, plain_len);
    memset(buf + aad_len + plain_len, 0, AES128GCM_TAG_LEN);

    sg_init_one(&sg, buf, buf_len);
    crypto_init_wait(&wait);
    aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                              crypto_req_done, &wait);
    aead_request_set_crypt(req, &sg, &sg, plain_len, (u8 *)nonce);
    aead_request_set_ad(req, aad_len);

    ret = crypto_wait_req(crypto_aead_encrypt(req), &wait);
    if (!ret)
        /* ciphertext+tag starts at buf+aad_len */
        memcpy(out, buf + aad_len, plain_len + AES128GCM_TAG_LEN);

    kfree(buf);
free_req:
    aead_request_free(req);
free_tfm:
    crypto_free_aead(tfm);
    return ret;
}

/*
 * Decrypt ciphertext (cipher_len includes the 16-byte tag) -> plaintext.
 * On success writes cipher_len - TAG_LEN bytes to out.
 */
static int aes128gcm_dec(const u8 key[AES128GCM_KEY_LEN],
                         const u8 nonce[AES128GCM_IV_LEN],
                         const u8 *aad, size_t aad_len,
                         const u8 *cipher, size_t cipher_len,
                         u8 *out /* cipher_len - TAG_LEN */)
{
    struct crypto_aead *tfm;
    struct aead_request *req;
    struct scatterlist  sg;
    struct crypto_wait  wait;
    u8  *buf;
    size_t buf_len = aad_len + cipher_len;
    int ret;

    if (cipher_len < AES128GCM_TAG_LEN) return -EINVAL;

    tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
    if (IS_ERR(tfm)) return PTR_ERR(tfm);
    ret = crypto_aead_setkey(tfm, key, AES128GCM_KEY_LEN);
    if (ret) goto free_tfm;
    ret = crypto_aead_setauthsize(tfm, AES128GCM_TAG_LEN);
    if (ret) goto free_tfm;

    req = aead_request_alloc(tfm, GFP_KERNEL);
    if (!req) { ret = -ENOMEM; goto free_tfm; }

    buf = kmalloc(buf_len, GFP_KERNEL);
    if (!buf) { ret = -ENOMEM; goto free_req; }

    memcpy(buf, aad, aad_len);
    memcpy(buf + aad_len, cipher, cipher_len);

    sg_init_one(&sg, buf, buf_len);
    crypto_init_wait(&wait);
    aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                              crypto_req_done, &wait);
    aead_request_set_crypt(req, &sg, &sg, cipher_len, (u8 *)nonce);
    aead_request_set_ad(req, aad_len);

    ret = crypto_wait_req(crypto_aead_decrypt(req), &wait);
    if (!ret)
        memcpy(out, buf + aad_len, cipher_len - AES128GCM_TAG_LEN);

    kfree(buf);
free_req:
    aead_request_free(req);
free_tfm:
    crypto_free_aead(tfm);
    return ret;
}

/* ------------------------------------------------------------------ */
/*  TLS record layer                                                   */
/* ------------------------------------------------------------------ */

/* Send a raw (plaintext) TLS record */
static int send_plain_record(struct socket *sock, u8 ctype,
                              const u8 *data, size_t dlen)
{
    u8 hdr[5] = { ctype, 0x03, 0x01,
                  (u8)(dlen >> 8), (u8)(dlen & 0xff) };
    int ret = tls_send_all(sock, hdr, 5);
    if (ret) return ret;
    return tls_send_all(sock, data, dlen);
}

/* Receive a raw (plaintext) TLS record; *data is kmalloc'd, caller frees */
static int recv_plain_record(struct socket *sock, u8 *ctype,
                              u8 **data, size_t *dlen)
{
    u8 hdr[5];
    size_t len;
    u8 *buf;
    int ret;

retry:
    ret = tls_recv_all(sock, hdr, 5);
    if (ret < 0) return ret;

    /* Skip CCS (TLS 1.3 middlebox compat) */
    if (hdr[0] == TLS_CONTENT_CCS) {
        u8 dummy;
        tls_recv_all(sock, &dummy, 1);
        goto retry;
    }

    *ctype = hdr[0];
    len = ((size_t)hdr[3] << 8) | hdr[4];
    if (len == 0 || len > 16640) return -EMSGSIZE;

    buf = kmalloc(len + 1, GFP_KERNEL);
    if (!buf) return -ENOMEM;

    ret = tls_recv_all(sock, buf, len);
    if (ret < 0) { kfree(buf); return ret; }
    buf[len] = '\0';
    *data = buf;
    *dlen = len;
    return 0;
}

/*
 * Send one encrypted TLS 1.3 record.
 * inner_type: the real ContentType byte appended inside the plaintext.
 */
static int send_enc_record(struct tls13_ctx *ctx,
                           const u8 *key, const u8 *iv, u64 *seq,
                           u8 inner_type,
                           const u8 *plain, size_t plain_len)
{
    /* InnerPlaintext = plain || inner_type */
    size_t inner_len  = plain_len + 1;
    size_t cipher_len = inner_len + AES128GCM_TAG_LEN;
    u8 aad[5]  = { TLS_CONTENT_APPDATA, 0x03, 0x03,
                   (u8)(cipher_len >> 8), (u8)(cipher_len & 0xff) };
    u8  nonce[AES128GCM_IV_LEN];
    u8 *inner  = NULL;
    u8 *cipher = NULL;
    int ret;

    inner  = kmalloc(inner_len,  GFP_KERNEL);
    cipher = kmalloc(cipher_len, GFP_KERNEL);
    if (!inner || !cipher) { ret = -ENOMEM; goto out; }

    memcpy(inner, plain, plain_len);
    inner[plain_len] = inner_type;

    make_nonce(iv, *seq, nonce);
    (*seq)++;

    ret = aes128gcm_enc(key, nonce, aad, 5, inner, inner_len, cipher);
    if (ret) goto out;

    ret = tls_send_all(ctx->sock, aad, 5);
    if (!ret) ret = tls_send_all(ctx->sock, cipher, cipher_len);
out:
    kfree(inner);
    kfree(cipher);
    return ret;
}

/*
 * Receive one encrypted TLS 1.3 record.
 * *inner_type set to the real ContentType; *payload kmalloc'd, caller frees.
 */
static int recv_enc_record(struct tls13_ctx *ctx,
                           const u8 *key, const u8 *iv, u64 *seq,
                           u8 *inner_type, u8 **payload, size_t *plen)
{
    u8 hdr[5];
    size_t record_len, plain_len;
    u8 *cipher = NULL, *plain = NULL;
    u8  nonce[AES128GCM_IV_LEN];
    int ret;

retry:
    ret = tls_recv_all(ctx->sock, hdr, 5);
    if (ret < 0) return ret;
    if (ret > 0 && ret < 5) return -ECONNRESET; /* partial header */

    if (hdr[0] == TLS_CONTENT_CCS) {
        u8 dummy;
        tls_recv_all(ctx->sock, &dummy, 1);
        goto retry;
    }

    record_len = ((size_t)hdr[3] << 8) | hdr[4];
    if (record_len < AES128GCM_TAG_LEN || record_len > 16640 + AES128GCM_TAG_LEN)
        return -EMSGSIZE;

    cipher = kmalloc(record_len, GFP_KERNEL);
    if (!cipher) return -ENOMEM;

    ret = tls_recv_all(ctx->sock, cipher, record_len);
    if (ret < 0) goto out_free;

    /* plain_len = cipher_len - tag, need +1 for null term */
    plain_len = record_len - AES128GCM_TAG_LEN;
    plain = kmalloc(plain_len + 1, GFP_KERNEL);
    if (!plain) { ret = -ENOMEM; goto out_free; }

    make_nonce(iv, *seq, nonce);
    (*seq)++;

    ret = aes128gcm_dec(key, nonce, hdr, 5, cipher, record_len, plain);
    if (ret) {
        printk(KERN_ERR "kwebdavfs/tls: dec failed seq=%llu rtype=%u rlen=%zu: %d\n",
               *seq - 1, hdr[0], record_len, ret);
        goto out_free;
    }

    /* Strip trailing zeros, last non-zero byte is real ContentType */
    while (plain_len > 0 && plain[plain_len - 1] == 0)
        plain_len--;
    if (plain_len == 0) { ret = -EBADMSG; goto out_free; }

    *inner_type = plain[--plain_len];
    plain[plain_len] = '\0';

    kfree(cipher);
    *payload = plain;
    *plen    = plain_len;
    return 0;

out_free:
    kfree(cipher);
    kfree(plain);
    return ret;
}

/* ------------------------------------------------------------------ */
/*  ClientHello builder                                                */
/* ------------------------------------------------------------------ */
static u8 *build_client_hello(const u8 pub_wire[P256_PUB_WIRE_LEN],
                               const char *hostname,
                               const u8 random[32],
                               size_t *out_len)
{
    size_t hlen = strlen(hostname);

    /* Extension lengths */
    size_t sni_body = 2 + 1 + 2 + hlen;
    size_t sni_ext  = 4 + sni_body;
    size_t sg_ext   = 4 + 4;             /* supported_groups: P-256 */
    size_t sv_ext   = 4 + 3;             /* supported_versions */
    size_t sa_ext   = 4 + 8;             /* signature_algorithms */
    size_t ks_ext   = 4 + 2 + 4 + P256_PUB_WIRE_LEN; /* key_share: 65-byte point */

    size_t ext_total = sni_ext + sg_ext + sv_ext + sa_ext + ks_ext;
    size_t body_len  = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + ext_total;
    size_t total     = 4 + body_len;

    u8 *buf = kzalloc(total, GFP_KERNEL);
    if (!buf) return NULL;

    size_t p = 0;
#define W1(v)   (buf[p++] = (u8)(v))
#define W2(v)   do { W1((v)>>8); W1((v)&0xff); } while(0)
#define W3(v)   do { W1((v)>>16); W1((v)>>8); W1((v)&0xff); } while(0)
#define WN(s,n) do { memcpy(&buf[p], (s), (n)); p += (n); } while(0)

    /* Handshake header */
    W1(TLS_HS_CLIENT_HELLO); W3(body_len);

    /* ClientHello body */
    W2(0x0303); WN(random, 32); W1(0);
    W2(2); W2(TLS_CIPHER_AES128_GCM_SHA256);
    W1(1); W1(0);
    W2(ext_total);

    /* server_name */
    W2(TLS_EXT_SERVER_NAME); W2(sni_body);
    W2(sni_body - 2); W1(0); W2(hlen); WN(hostname, hlen);

    /* supported_groups: P-256 only */
    W2(TLS_EXT_SUPPORTED_GROUPS); W2(4);
    W2(2); W2(TLS_GROUP_P256);

    /* supported_versions: TLS 1.3 */
    W2(TLS_EXT_SUPPORTED_VERSIONS); W2(3);
    W1(2); W2(0x0304);

    /* signature_algorithms */
    W2(TLS_EXT_SIG_ALGS); W2(8); W2(6);
    W2(0x0403); W2(0x0804); W2(0x0401);

    /* key_share: P-256, 65-byte uncompressed EC point */
    W2(TLS_EXT_KEY_SHARE);
    W2(2 + 2 + 2 + P256_PUB_WIRE_LEN);
    W2(2 + 2 + P256_PUB_WIRE_LEN);
    W2(TLS_GROUP_P256);
    W2(P256_PUB_WIRE_LEN);
    WN(pub_wire, P256_PUB_WIRE_LEN);

#undef W1
#undef W2
#undef W3
#undef WN

    *out_len = total;
    return buf;
}

/* ------------------------------------------------------------------ */
/*  ServerHello parser  - extracts server x25519 public key           */
/* ------------------------------------------------------------------ */
static int parse_server_hello(const u8 *body, size_t blen,
                               u8 srv_wire[P256_PUB_WIRE_LEN])
{
    size_t p;
    u16 ext_total;

    /* legacy_version(2) + random(32) + session_id_len(1) + session_id */
    if (blen < 35) return -EINVAL;
    p = 34;
    p += 1 + body[p];             /* skip session_id */
    p += 3;                       /* skip cipher_suite + compression */
    if (p + 2 > blen) return -EINVAL;
    ext_total = ((u16)body[p] << 8) | body[p+1]; p += 2;
    if (p + ext_total > blen) return -EINVAL;

    while (ext_total >= 4) {
        u16 ext_type = ((u16)body[p] << 8) | body[p+1];
        u16 ext_len  = ((u16)body[p+2] << 8) | body[p+3];
        p += 4; ext_total -= 4;
        if (ext_len > ext_total) return -EINVAL;

        if (ext_type == TLS_EXT_KEY_SHARE && ext_len >= 4) {
            u16 group  = ((u16)body[p]   << 8) | body[p+1];
            u16 keylen = ((u16)body[p+2] << 8) | body[p+3];
            if (group == TLS_GROUP_P256 && keylen == P256_PUB_WIRE_LEN
                && ext_len >= 4 + P256_PUB_WIRE_LEN) {
                memcpy(srv_wire, &body[p+4], P256_PUB_WIRE_LEN);
                return 0;
            }
        }
        p += ext_len; ext_total -= ext_len;
    }
    return -ENOKEY;
}

/* ------------------------------------------------------------------ */
/*  Key derivation                                                     */
/* ------------------------------------------------------------------ */
static int derive_handshake_keys(struct tls13_ctx *ctx,
                                  const u8 shared[P256_SHARED_LEN],
                                  const u8 th[SHA256_LEN])
{
    u8  zeros[SHA256_LEN] = {0};
    u8  empty_hash[SHA256_LEN];
    u8  early_secret[SHA256_LEN];
    u8  derived[SHA256_LEN];
    int ret;

    /* empty_hash = SHA-256("") */
    ret = do_sha256(ctx->sha256, NULL, 0, empty_hash);
    if (ret) return ret;

    /* Early secret: HKDF-Extract(salt=zeros, IKM=zeros) */
    ret = hkdf_extract(ctx->hmac_sha256, zeros, SHA256_LEN,
                       zeros, SHA256_LEN, early_secret);
    if (ret) return ret;

    /* derived = HKDF-Expand-Label(early_secret, "derived", empty_hash, 32) */
    ret = hkdf_expand_label(ctx->hmac_sha256,
                             early_secret, SHA256_LEN,
                             "derived", 7,
                             empty_hash, SHA256_LEN,
                             derived, SHA256_LEN);
    if (ret) return ret;

    /* Handshake secret: HKDF-Extract(salt=derived, IKM=shared) */
    ret = hkdf_extract(ctx->hmac_sha256, shared, P256_SHARED_LEN,
                       derived, SHA256_LEN, ctx->handshake_secret);
    if (ret) return ret;

    /* client/server handshake traffic secrets */
    ret = hkdf_expand_label(ctx->hmac_sha256,
                             ctx->handshake_secret, SHA256_LEN,
                             "c hs traffic", 12, th, SHA256_LEN,
                             ctx->client_hs_secret, SHA256_LEN);
    if (ret) return ret;
    ret = hkdf_expand_label(ctx->hmac_sha256,
                             ctx->handshake_secret, SHA256_LEN,
                             "s hs traffic", 12, th, SHA256_LEN,
                             ctx->server_hs_secret, SHA256_LEN);
    if (ret) return ret;

    /* Derive traffic keys: key (16 bytes) + iv (12 bytes) */
#define DERIV_KEY_IV(secret, key, iv) do { \
    ret = hkdf_expand_label(ctx->hmac_sha256, secret, SHA256_LEN, \
                             "key", 3, NULL, 0, key, AES128GCM_KEY_LEN); \
    if (!ret) ret = hkdf_expand_label(ctx->hmac_sha256, secret, SHA256_LEN, \
                             "iv", 2, NULL, 0, iv, AES128GCM_IV_LEN); \
    if (ret) return ret; \
} while(0)

    DERIV_KEY_IV(ctx->client_hs_secret, ctx->c_hs_key, ctx->c_hs_iv);
    DERIV_KEY_IV(ctx->server_hs_secret, ctx->s_hs_key, ctx->s_hs_iv);
#undef DERIV_KEY_IV
    return 0;
}

static int derive_app_keys(struct tls13_ctx *ctx, const u8 th[SHA256_LEN])
{
    u8  zeros[SHA256_LEN] = {0};
    u8  empty_hash[SHA256_LEN];
    u8  derived[SHA256_LEN];
    u8  master[SHA256_LEN];
    u8  c_app[SHA256_LEN], s_app[SHA256_LEN];
    int ret;

    ret = do_sha256(ctx->sha256, NULL, 0, empty_hash);
    if (ret) return ret;

    ret = hkdf_expand_label(ctx->hmac_sha256,
                             ctx->handshake_secret, SHA256_LEN,
                             "derived", 7, empty_hash, SHA256_LEN,
                             derived, SHA256_LEN);
    if (ret) return ret;

    ret = hkdf_extract(ctx->hmac_sha256, zeros, SHA256_LEN,
                       derived, SHA256_LEN, master);
    if (ret) return ret;

    ret = hkdf_expand_label(ctx->hmac_sha256, master, SHA256_LEN,
                             "c ap traffic", 12, th, SHA256_LEN,
                             c_app, SHA256_LEN);
    if (ret) return ret;
    ret = hkdf_expand_label(ctx->hmac_sha256, master, SHA256_LEN,
                             "s ap traffic", 12, th, SHA256_LEN,
                             s_app, SHA256_LEN);
    if (ret) return ret;

#define DERIV_KEY_IV(secret, key, iv) do { \
    ret = hkdf_expand_label(ctx->hmac_sha256, secret, SHA256_LEN, \
                             "key", 3, NULL, 0, key, AES128GCM_KEY_LEN); \
    if (!ret) ret = hkdf_expand_label(ctx->hmac_sha256, secret, SHA256_LEN, \
                             "iv", 2, NULL, 0, iv, AES128GCM_IV_LEN); \
    if (ret) return ret; \
} while(0)
    DERIV_KEY_IV(c_app, ctx->c_app_key, ctx->c_app_iv);
    DERIV_KEY_IV(s_app, ctx->s_app_key, ctx->s_app_iv);
#undef DERIV_KEY_IV
    return 0;
}

/* ------------------------------------------------------------------ */
/*  tls13_connect                                                      */
/* ------------------------------------------------------------------ */
int tls13_connect(struct socket *sock, const char *hostname,
                  struct tls13_ctx **out)
{
    struct tls13_ctx *ctx;
    u8  random[32];
    u8  pub_wire[P256_PUB_WIRE_LEN];   /* our public key (wire format) */
    u8  srv_wire[P256_PUB_WIRE_LEN];   /* server's public key */
    u8  shared[P256_SHARED_LEN];
    u8  th[SHA256_LEN];
    u8 *hello = NULL;
    size_t hello_len = 0;
    u8 *payload = NULL;
    size_t plen = 0;
    u8  ctype;
    int ret;

    ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx) return -ENOMEM;
    ctx->sock = sock;

    ctx->sha256 = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(ctx->sha256)) {
        ret = PTR_ERR(ctx->sha256); ctx->sha256 = NULL; goto err;
    }
    ctx->hmac_sha256 = crypto_alloc_shash("hmac(sha256)", 0, 0);
    if (IS_ERR(ctx->hmac_sha256)) {
        ret = PTR_ERR(ctx->hmac_sha256); ctx->hmac_sha256 = NULL; goto err;
    }

    /* Generate P-256 ephemeral key pair */
    ctx->kpp = p256_gen_keypair(pub_wire);
    if (IS_ERR(ctx->kpp)) {
        ret = PTR_ERR(ctx->kpp); ctx->kpp = NULL; goto err;
    }

    get_random_bytes(random, sizeof(random));

    /* Build and send ClientHello */
    hello = build_client_hello(pub_wire, hostname, random, &hello_len);
    if (!hello) { ret = -ENOMEM; goto err; }

    ret = tscript_add(ctx, hello, hello_len);
    if (ret) goto err;

    /* Send ClientHello as TLS 1.0 compat record (legacy_version = 0x0301) */
    {
        u8 hdr[5] = { TLS_CONTENT_HANDSHAKE, 0x03, 0x01,
                      (u8)(hello_len >> 8), (u8)(hello_len & 0xff) };
        ret = tls_send_all(sock, hdr, 5);
        if (!ret) ret = tls_send_all(sock, hello, hello_len);
    }
    kfree(hello); hello = NULL;
    if (ret) { printk(KERN_ERR "kwebdavfs/tls: send ClientHello: %d\n", ret); goto err; }

    /* Receive ServerHello */
    ret = recv_plain_record(sock, &ctype, &payload, &plen);
    if (ret) goto err;
    if (ctype != TLS_CONTENT_HANDSHAKE || plen < 4 ||
        payload[0] != TLS_HS_SERVER_HELLO) {
        printk(KERN_ERR "kwebdavfs/tls: expected ServerHello, got type=%u hs=%u\n",
               ctype, payload ? payload[0] : 0xff);
        kfree(payload);
        ret = -EPROTO; goto err;
    }

    /* Add ServerHello to transcript */
    ret = tscript_add(ctx, payload, plen);
    if (ret) { kfree(payload); goto err; }

    /* Parse ServerHello body (skip 4-byte handshake header) */
    ret = parse_server_hello(payload + 4, plen - 4, srv_wire);
    kfree(payload); payload = NULL;
    if (ret) {
        printk(KERN_ERR "kwebdavfs/tls: parse ServerHello: %d\n", ret);
        goto err;
    }

    /* Compute P-256 shared secret */
    ret = p256_shared_secret(ctx->kpp, srv_wire, shared);
    crypto_free_kpp(ctx->kpp); ctx->kpp = NULL;
    if (ret) { printk(KERN_ERR "kwebdavfs/tls: ECDH failed: %d\n", ret); goto err; }

    /* Transcript hash = SHA-256(ClientHello || ServerHello) */
    ret = tscript_hash(ctx, th);
    if (ret) goto err;

    /* Derive handshake traffic keys */
    ret = derive_handshake_keys(ctx, shared, th);
    memzero_explicit(shared, sizeof(shared));
    if (ret) { printk(KERN_ERR "kwebdavfs/tls: hs key derivation: %d\n", ret); goto err; }

    /* Consume server's encrypted handshake messages until Finished */
    {
        bool got_finished = false;
        int  guard = 30;

        while (!got_finished && guard-- > 0) {
            u8 inner;
            u8 *rec = NULL;
            size_t rlen = 0;

            ret = recv_enc_record(ctx,
                                   ctx->s_hs_key, ctx->s_hs_iv,
                                   &ctx->s_hs_seq,
                                   &inner, &rec, &rlen);
            if (ret) goto err;

            if (inner == TLS_CONTENT_ALERT) {
                kfree(rec);
                ret = -ECONNRESET;
                goto err;
            }

            if (inner == TLS_CONTENT_HANDSHAKE && rlen >= 4) {
                /* A single encrypted record may carry multiple hs msgs */
                size_t off = 0;
                while (off + 4 <= rlen) {
                    u8  mtype = rec[off];
                    u32 mlen  = ((u32)rec[off+1] << 16) |
                                ((u32)rec[off+2] <<  8) |  rec[off+3];
                    if (off + 4 + mlen > rlen) break;

                    /* Add this message to transcript */
                    tscript_add(ctx, &rec[off], 4 + mlen);

                    if (mtype == TLS_HS_FINISHED)
                        got_finished = true;

                    off += 4 + mlen;
                }
            }
            kfree(rec);
        }

        if (!got_finished) {
            printk(KERN_ERR "kwebdavfs/tls: no server Finished message\n");
            ret = -EPROTO; goto err;
        }
    }

    /* Derive application traffic keys */
    ret = tscript_hash(ctx, th);
    if (ret) goto err;
    ret = derive_app_keys(ctx, th);
    if (ret) { printk(KERN_ERR "kwebdavfs/tls: app key derivation: %d\n", ret); goto err; }

    /* Build and send client Finished */
    {
        u8 fin_key[SHA256_LEN];
        u8 verify[SHA256_LEN];
        u8 cur_hash[SHA256_LEN];
        u8 fin_msg[4 + SHA256_LEN];

        /* finished_key = HKDF-Expand-Label(client_hs_secret,"finished","",32) */
        ret = hkdf_expand_label(ctx->hmac_sha256,
                                ctx->client_hs_secret, SHA256_LEN,
                                "finished", 8, NULL, 0,
                                fin_key, SHA256_LEN);
        if (ret) goto err;

        /* verify_data = HMAC-SHA256(fin_key, transcript_hash) */
        tscript_hash(ctx, cur_hash);
        do_hmac_sha256(ctx->hmac_sha256,
                       fin_key, SHA256_LEN,
                       cur_hash, SHA256_LEN,
                       verify);

        fin_msg[0] = TLS_HS_FINISHED;
        fin_msg[1] = 0; fin_msg[2] = 0; fin_msg[3] = SHA256_LEN;
        memcpy(&fin_msg[4], verify, SHA256_LEN);

        /* Add to transcript */
        tscript_add(ctx, fin_msg, sizeof(fin_msg));

        /* Encrypt and send with handshake keys */
        ret = send_enc_record(ctx,
                              ctx->c_hs_key, ctx->c_hs_iv, &ctx->c_hs_seq,
                              TLS_CONTENT_HANDSHAKE,
                              fin_msg, sizeof(fin_msg));
        if (ret) goto err;
    }

    ctx->handshake_done = true;
    *out = ctx;
    printk(KERN_INFO "kwebdavfs/tls: TLS 1.3 handshake OK (AES-128-GCM-SHA256)\n");
    return 0;

err:
    kfree(hello);
    tls13_free(ctx);
    return ret;
}

/* ------------------------------------------------------------------ */
/*  Application data send / recv                                      */
/* ------------------------------------------------------------------ */
int tls13_send(struct tls13_ctx *ctx, const void *data, size_t len)
{
    if (!ctx || !ctx->handshake_done) return -EINVAL;
    return send_enc_record(ctx,
                           ctx->c_app_key, ctx->c_app_iv, &ctx->c_app_seq,
                           TLS_CONTENT_APPDATA, data, len);
}

int tls13_recv(struct tls13_ctx *ctx, void *buf, size_t len, int flags)
{
    u8     inner_type;
    u8    *payload;
    size_t plen;
    int    ret;

    if (!ctx) {
        printk(KERN_ERR "kwebdavfs/tls: tls13_recv: ctx=NULL\n");
        return -EINVAL;
    }
    if (!ctx->handshake_done) {
        printk(KERN_ERR "kwebdavfs/tls: tls13_recv: handshake not done\n");
        return -EINVAL;
    }

retry_recv:
    ret = recv_enc_record(ctx,
                          ctx->s_app_key, ctx->s_app_iv, &ctx->s_app_seq,
                          &inner_type, &payload, &plen);
    if (ret) {
        printk(KERN_ERR "kwebdavfs/tls: tls13_recv: recv_enc_record=%d\n", ret);
        return ret;
    }

    if (inner_type == TLS_CONTENT_ALERT) {
        kfree(payload);
        return 0; /* EOF / close_notify */
    }

    /* Skip NewSessionTicket and other handshake messages that arrive
     * after handshake completes (server sends with app keys) */
    if (inner_type == TLS_CONTENT_HANDSHAKE) {
        printk(KERN_DEBUG "kwebdavfs/tls: skipping post-handshake hs record\n");
        kfree(payload);
        goto retry_recv;
    }

    plen = min(plen, len);
    memcpy(buf, payload, plen);
    kfree(payload);
    return (int)plen;
}

/* ------------------------------------------------------------------ */
/*  Cleanup                                                            */
/* ------------------------------------------------------------------ */
void tls13_free(struct tls13_ctx *ctx)
{
    if (!ctx) return;
    if (ctx->kpp)         crypto_free_kpp(ctx->kpp);
    if (ctx->sha256)      crypto_free_shash(ctx->sha256);
    if (ctx->hmac_sha256) crypto_free_shash(ctx->hmac_sha256);
    kfree(ctx->transcript);
    memzero_explicit(ctx, sizeof(*ctx));
    kfree(ctx);
}
