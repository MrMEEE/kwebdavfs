#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/inet.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/sched/signal.h>
#include <linux/dns_resolver.h>
#include <net/sock.h>
#include <net/tcp.h>
#include "tls.h"

#include "kwebdavfs.h"

/* Simple HTTP client implementation for kernel space */

struct http_request {
    char *method;
    char *url;
    char *host;
    char *path;
    char *body;
    size_t body_len;
    char *auth_header;
    char *extra_headers;  /* optional additional headers, each "Key: Value\r\n" */
};

static char *webdav_method_names[] = {
    [WEBDAV_GET] = "GET",
    [WEBDAV_PUT] = "PUT",
    [WEBDAV_PROPFIND] = "PROPFIND",
    [WEBDAV_PROPPATCH] = "PROPPATCH", 
    [WEBDAV_MKCOL] = "MKCOL",
    [WEBDAV_DELETE] = "DELETE",
    [WEBDAV_COPY] = "COPY",
    [WEBDAV_MOVE] = "MOVE",
    [WEBDAV_HEAD] = "HEAD",
    [WEBDAV_OPTIONS] = "OPTIONS"
};

/* DNS resolution helper */
static int resolve_hostname(const char *hostname, struct sockaddr_in *addr)
{
    char *ip_addr = NULL;
    int ret;

    /* First try to parse as IP address */
    if (in4_pton(hostname, -1, (u8 *)&addr->sin_addr.s_addr, -1, NULL))
        return 0;

    /* Use kernel DNS resolver */
    ret = dns_query(&init_net, NULL, hostname, strlen(hostname),
                    NULL, &ip_addr, NULL, false);
    if (ret < 0) {
        printk(KERN_ERR "kwebdavfs: failed to resolve %s: %d\n", hostname, ret);
        return ret;
    }

    if (!in4_pton(ip_addr, -1, (u8 *)&addr->sin_addr.s_addr, -1, NULL)) {
        printk(KERN_ERR "kwebdavfs: dns_query returned non-IPv4 result '%s'\n", ip_addr);
        kfree(ip_addr);
        return -EINVAL;
    }

    printk(KERN_DEBUG "kwebdavfs: resolved %s -> %s\n", hostname, ip_addr);
    kfree(ip_addr);
    return 0;
}

/* Thin wrapper so callers can get a tls13_ctx without knowing internals */
static int upgrade_to_tls(struct socket *sock, const char *host,
                           struct tls13_ctx **ctxp)
{
    return tls13_connect(sock, host, ctxp);
}

int kwebdavfs_http_init(void)
{
    printk(KERN_INFO "kwebdavfs: HTTP client initialized (DNS: enabled, TLS: basic support)\n");
    return 0;
}

void kwebdavfs_http_exit(void)
{
    printk(KERN_INFO "kwebdavfs: HTTP client cleaned up\n");
}

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t base64_encode(const u8 *src, size_t slen, char *dst)
{
    size_t i, dpos = 0;
    for (i = 0; i + 2 < slen; i += 3) {
        dst[dpos++] = b64_table[src[i] >> 2];
        dst[dpos++] = b64_table[((src[i] & 3) << 4) | (src[i+1] >> 4)];
        dst[dpos++] = b64_table[((src[i+1] & 0xf) << 2) | (src[i+2] >> 6)];
        dst[dpos++] = b64_table[src[i+2] & 0x3f];
    }
    if (slen - i == 2) {
        dst[dpos++] = b64_table[src[i] >> 2];
        dst[dpos++] = b64_table[((src[i] & 3) << 4) | (src[i+1] >> 4)];
        dst[dpos++] = b64_table[(src[i+1] & 0xf) << 2];
        dst[dpos++] = '=';
    } else if (slen - i == 1) {
        dst[dpos++] = b64_table[src[i] >> 2];
        dst[dpos++] = b64_table[(src[i] & 3) << 4];
        dst[dpos++] = '=';
        dst[dpos++] = '=';
    }
    dst[dpos] = '\0';
    return dpos;
}

static char *build_auth_header(const char *username, const char *password)
{
    char *cred, *header;
    size_t cred_len, b64_len, hdr_len;

    if (!username || !password)
        return NULL;

    cred_len = strlen(username) + 1 + strlen(password);
    cred = kmalloc(cred_len + 1, GFP_KERNEL);
    if (!cred)
        return NULL;
    snprintf(cred, cred_len + 1, "%s:%s", username, password);

    b64_len = ((cred_len + 2) / 3) * 4;
    hdr_len = strlen("Authorization: Basic ") + b64_len + 4; /* \r\n\0 */
    header = kmalloc(hdr_len, GFP_KERNEL);
    if (!header) { kfree(cred); return NULL; }

    memcpy(header, "Authorization: Basic ", 21);
    base64_encode((u8 *)cred, cred_len, header + 21);
    strlcat(header, "\r\n", hdr_len);

    kfree(cred);
    return header;
}

static int parse_url(const char *url, char **host, char **path, int *port, bool *use_ssl)
{
    const char *p, *host_start, *path_start;
    size_t host_len;
    
    *host = NULL;
    *path = NULL;
    *port = 80;
    *use_ssl = false;
    
    if (strncmp(url, "http://", 7) == 0) {
        host_start = url + 7;
        *port = 80;
    } else if (strncmp(url, "https://", 8) == 0) {
        host_start = url + 8;
        *port = 443;
        *use_ssl = true;
    } else {
        return -EINVAL;
    }
    
    /* Find path start */
    path_start = strchr(host_start, '/');
    if (!path_start) {
        *path = kstrdup("/", GFP_KERNEL);
        host_len = strlen(host_start);
    } else {
        *path = kstrdup(path_start, GFP_KERNEL);
        host_len = path_start - host_start;
    }
    
    if (!*path)
        return -ENOMEM;
    
    /* Extract host (and port if specified) */
    p = memchr(host_start, ':', host_len);
    if (p) {
        *port = simple_strtol(p + 1, NULL, 10);
        host_len = p - host_start;
    }
    
    *host = kmalloc(host_len + 1, GFP_KERNEL);
    if (!*host) {
        kfree(*path);
        return -ENOMEM;
    }
    
    memcpy(*host, host_start, host_len);
    (*host)[host_len] = '\0';
    
    return 0;
}

static int send_http_request(struct socket *sock, struct tls13_ctx *tls,
                              struct http_request *req)
{
    struct msghdr msg;
    struct kvec iov;
    char *full_request;
    size_t buf_size, hdr_len;
    bool is_propfind = (strcmp(req->method, "PROPFIND") == 0 ||
                        strcmp(req->method, "PROPPATCH") == 0);
    int ret;

    /* Headers only — body is sent separately below */
    buf_size = strlen(req->method) + strlen(req->path) + strlen(req->host)
               + (req->auth_header ? strlen(req->auth_header) : 0)
               + (req->extra_headers ? strlen(req->extra_headers) : 0)
               + 512;

    full_request = kmalloc(buf_size, GFP_KERNEL);
    if (!full_request)
        return -ENOMEM;

    /* Request line */
    hdr_len = 0;
    hdr_len += snprintf(full_request + hdr_len, buf_size - hdr_len,
                        "%s %s HTTP/1.1\r\n", req->method, req->path);

    /* Mandatory headers */
    hdr_len += snprintf(full_request + hdr_len, buf_size - hdr_len,
                        "Host: %s\r\n"
                        "User-Agent: kwebdavfs/%s\r\n"
                        "Connection: close\r\n",
                        req->host, KWEBDAVFS_VERSION);

    /* Auth header (already includes \r\n) */
    if (req->auth_header)
        hdr_len += snprintf(full_request + hdr_len, buf_size - hdr_len,
                            "%s", req->auth_header);

    /* Extra headers (e.g. Destination for MOVE) */
    if (req->extra_headers)
        hdr_len += snprintf(full_request + hdr_len, buf_size - hdr_len,
                            "%s", req->extra_headers);

    /* PROPFIND-specific headers */
    if (is_propfind)
        hdr_len += snprintf(full_request + hdr_len, buf_size - hdr_len,
                            "Depth: 1\r\n");

    /* Body headers */
    if (req->body_len > 0) {
        hdr_len += snprintf(full_request + hdr_len, buf_size - hdr_len,
                            "Content-Type: application/xml; charset=utf-8\r\n"
                            "Content-Length: %zu\r\n",
                            req->body_len);
    }

    /* End of headers */
    hdr_len += snprintf(full_request + hdr_len, buf_size - hdr_len, "\r\n");

    /* Send headers */
    memset(&msg, 0, sizeof(msg));
    iov.iov_base = full_request;
    iov.iov_len  = hdr_len;

    if (tls)
        ret = tls13_send(tls, full_request, hdr_len);
    else
        ret = kernel_sendmsg(sock, &msg, &iov, 1, hdr_len);
    if (ret < 0) {
        kfree(full_request);
        return ret;
    }
    kfree(full_request);

    /* Send body separately in chunks — avoids giant kmalloc for large files */
    if (req->body && req->body_len > 0) {
        const size_t SEND_CHUNK = 131072; /* 128 KB */
        size_t sent = 0;
        while (sent < req->body_len) {
            size_t chunk = min(req->body_len - sent, SEND_CHUNK);
            if (tls) {
                /* tls13_send is all-or-nothing: returns 0 on success, <0 on error */
                ret = tls13_send(tls, req->body + sent, chunk);
                if (ret < 0) return ret;
                sent += chunk;
            } else {
                memset(&msg, 0, sizeof(msg));
                iov.iov_base = (char *)req->body + sent;
                iov.iov_len  = chunk;
                ret = kernel_sendmsg(sock, &msg, &iov, 1, chunk);
                if (ret < 0) return ret;
                sent += ret;
            }
        }
    }
    return 0;
}

/* Max sizes for response reading */
#define KWEBDAV_HDR_BUF     16384                   /* 16 KB  — headers      */
#define KWEBDAV_READ_CHUNK  65536                   /* 64 KB  — body chunks  */
#define KWEBDAV_MAX_BODY   (256 * 1024 * 1024)      /* 256 MB — hard cap     */

/*
 * Decode HTTP/1.1 chunked transfer encoding in-place.
 * Input:  buf[0..len) contains the raw chunked body (chunk-size CRLF data CRLF ...)
 * Output: buf is overwritten with the decoded body; *out_len receives decoded length.
 * Returns 0 on success, -EINVAL on malformed input (partial result still in buf).
 */
static int decode_chunked_inplace(char *buf, size_t len, size_t *out_len)
{
    char   *src = buf;
    char   *dst = buf;
    char   *end = buf + len;

    while (src < end) {
        /* Find end of chunk-size line */
        char *crlf = memchr(src, '\r', end - src);
        if (!crlf || crlf + 1 >= end || crlf[1] != '\n')
            break; /* truncated */

        /* Parse hex chunk size (ignore chunk extensions after ';') */
        unsigned long chunk_size = 0;
        char *p = src;
        while (p < crlf) {
            int nib;
            if (*p >= '0' && *p <= '9')      nib = *p - '0';
            else if (*p >= 'a' && *p <= 'f') nib = *p - 'a' + 10;
            else if (*p >= 'A' && *p <= 'F') nib = *p - 'A' + 10;
            else break; /* hit extension or invalid char */
            chunk_size = (chunk_size << 4) | nib;
            p++;
        }
        src = crlf + 2; /* skip size-line CRLF */

        if (chunk_size == 0)
            break; /* last chunk */

        if (src + chunk_size > end)
            chunk_size = end - src; /* truncated data — copy what we have */

        memmove(dst, src, chunk_size);
        dst += chunk_size;
        src += chunk_size;

        /* Skip trailing CRLF after chunk data */
        if (src + 1 < end && src[0] == '\r' && src[1] == '\n')
            src += 2;
    }
    *dst = '\0';
    *out_len = dst - buf;
    return 0;
}

static int receive_http_response(struct socket *sock, struct tls13_ctx *tls,
                                  struct webdav_response *response)
{
    struct msghdr  msg;
    struct kvec    iov;
    char          *hdr_buf, *headers_end, *content_start;
    int            hdr_received = 0, ret;
    long long      content_length = -1;
    bool           is_chunked = false;

    memset(response, 0, sizeof(*response));

    /* ---- Phase 1: read until we have complete headers (≤ 16 KB) ---- */
    hdr_buf = kmalloc(KWEBDAV_HDR_BUF, GFP_KERNEL);
    if (!hdr_buf)
        return -ENOMEM;

    for (;;) {
        int space = KWEBDAV_HDR_BUF - 1 - hdr_received;
        if (space <= 0) {
            printk(KERN_ERR "kwebdavfs: response headers exceed %d bytes\n",
                   KWEBDAV_HDR_BUF);
            kfree(hdr_buf);
            return -EMSGSIZE;
        }
        memset(&msg, 0, sizeof(msg));
        iov.iov_base = hdr_buf + hdr_received;
        iov.iov_len  = space;
        if (tls)
            ret = tls13_recv(tls, hdr_buf + hdr_received, space, 0);
        else
            ret = kernel_recvmsg(sock, &msg, &iov, 1, space, 0);
        if (ret < 0) {
            if ((ret == -ERESTARTSYS || ret == -EINTR) && !fatal_signal_pending(current))
                continue;
            kfree(hdr_buf);
            return ret;
        }
        if (ret == 0) break; /* EOF before headers complete */
        hdr_received += ret;
        hdr_buf[hdr_received] = '\0';
        if (strstr(hdr_buf, "\r\n\r\n"))
            break;
    }

    if (hdr_received == 0) { kfree(hdr_buf); return -ECONNRESET; }

    headers_end = strstr(hdr_buf, "\r\n\r\n");
    if (!headers_end) {
        printk(KERN_ERR "kwebdavfs: no header terminator\n");
        kfree(hdr_buf);
        return -EINVAL;
    }
    *headers_end = '\0'; /* null-terminate header block for sscanf/strstr */

    /* Parse status code */
    if (sscanf(hdr_buf, "HTTP/1.%*d %d", &response->status_code) != 1) {
        printk(KERN_ERR "kwebdavfs: bad status: %.60s\n", hdr_buf);
        kfree(hdr_buf);
        return -EINVAL;
    }

    /* Content-Length */
    {
        char *cl = strstr(hdr_buf, "Content-Length:");
        if (!cl) cl = strstr(hdr_buf, "content-length:");
        if (cl) {
            sscanf(cl + 15, " %lld", &content_length);
            response->content_length = content_length;
        }
    }

    /* Chunked transfer encoding */
    if (strstr(hdr_buf, "Transfer-Encoding: chunked") ||
        strstr(hdr_buf, "transfer-encoding: chunked"))
        is_chunked = true;

    /* ETag */
    {
        char *etag_line = strstr(hdr_buf, "ETag:");
        if (etag_line) {
            char *es = strchr(etag_line, '"');
            if (es) {
                char *ee = strchr(es + 1, '"');
                if (ee) {
                    size_t elen = ee - es - 1;
                    response->etag = kmalloc(elen + 1, GFP_KERNEL);
                    if (response->etag) {
                        memcpy(response->etag, es + 1, elen);
                        response->etag[elen] = '\0';
                    }
                }
            }
        }
    }

    /* Body bytes that overflowed into the header buffer */
    content_start = headers_end + 4;
    {
        int overflow = hdr_received - (int)(content_start - hdr_buf);
        if (overflow < 0) overflow = 0;

        /* ---- Phase 2: read body into a kvmalloc buffer ---- */
        if (content_length > 0) {
            /* Known length: allocate exactly */
            size_t cl = (size_t)content_length;
            char  *body;
            size_t got = 0;

            if (content_length > KWEBDAV_MAX_BODY) {
                printk(KERN_ERR "kwebdavfs: body too large (%lld)\n", content_length);
                kfree(hdr_buf);
                return -EFBIG;
            }
            body = kvmalloc(cl + 1, GFP_KERNEL);
            if (!body) { kfree(hdr_buf); return -ENOMEM; }

            if (overflow > 0) {
                size_t copy = min_t(size_t, (size_t)overflow, cl);
                memcpy(body, content_start, copy);
                got = copy;
            }
            while (got < cl) {
                int want = (int)min_t(size_t, cl - got, KWEBDAV_READ_CHUNK);
                memset(&msg, 0, sizeof(msg));
                iov.iov_base = body + got;
                iov.iov_len  = want;
                if (tls)
                    ret = tls13_recv(tls, body + got, want, 0);
                else
                    ret = kernel_recvmsg(sock, &msg, &iov, 1, want, 0);
                if (ret == -ERESTARTSYS || ret == -EINTR) continue;
                if (ret <= 0) break;
                got += ret;
            }
            body[got] = '\0';
            /* If server also set chunked encoding, decode it */
            if (is_chunked) {
                size_t decoded_len = 0;
                decode_chunked_inplace(body, got, &decoded_len);
                got = decoded_len;
            }
            response->data     = body;
            response->data_len = got;
        } else if (is_chunked || content_length < 0) {
            /* Unknown / chunked: grow buffer dynamically */
            size_t alloc = (size_t)overflow + KWEBDAV_READ_CHUNK;
            char  *body  = kvmalloc(alloc + 1, GFP_KERNEL);
            size_t got   = 0;

            if (!body) { kfree(hdr_buf); return -ENOMEM; }

            if (overflow > 0) {
                memcpy(body, content_start, overflow);
                got = overflow;
            }
            for (;;) {
                char *tmp;
                if (got >= KWEBDAV_MAX_BODY) break;
                if (got + KWEBDAV_READ_CHUNK > alloc) {
                    tmp = kvrealloc(body, alloc + KWEBDAV_READ_CHUNK + 1,
                                    GFP_KERNEL);
                    if (!tmp) break; /* keep what we have */
                    body   = tmp;
                    alloc += KWEBDAV_READ_CHUNK;
                }
                memset(&msg, 0, sizeof(msg));
                iov.iov_base = body + got;
                iov.iov_len  = KWEBDAV_READ_CHUNK;
                if (tls)
                    ret = tls13_recv(tls, body + got, KWEBDAV_READ_CHUNK, 0);
                else
                    ret = kernel_recvmsg(sock, &msg, &iov, 1, KWEBDAV_READ_CHUNK, 0);
                if (ret == -ERESTARTSYS || ret == -EINTR) continue;
                if (ret <= 0) break;
                got += ret;
            }
            body[got] = '\0';
            /* Decode chunked transfer encoding if needed */
            if (is_chunked) {
                size_t decoded_len = 0;
                decode_chunked_inplace(body, got, &decoded_len);
                got = decoded_len;
            }
            response->data     = body;
            response->data_len = got;
        }
    }

    printk(KERN_INFO "kwebdavfs: response status=%d body=%zu bytes\n",
           response->status_code, response->data_len);

    kfree(hdr_buf);
    return 0;
}

int kwebdavfs_http_request(struct kwebdavfs_fs_info *fsi, enum webdav_method method,
                          const char *url, const char *body, size_t body_len,
                          struct webdav_response *response)
{
    struct socket     *sock = NULL;
    struct tls13_ctx  *tls  = NULL;
    struct sockaddr_in addr;
    struct http_request req;
    char *host, *path;
    int  port, ret;
    bool use_ssl;

    if (!fsi || !url || !response)
        return -EINVAL;

    memset(&req, 0, sizeof(req));
    memset(response, 0, sizeof(*response));

    /* Parse URL */
    ret = parse_url(url, &host, &path, &port, &use_ssl);
    if (ret < 0)
        return ret;

    /* Create TCP socket */
    ret = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
    if (ret < 0)
        goto cleanup_url;

    /* Set send/receive timeouts so we never block forever */
    sock->sk->sk_rcvtimeo = msecs_to_jiffies(30000); /* 30 s */
    sock->sk->sk_sndtimeo = msecs_to_jiffies(30000); /* 30 s */

    /* Resolve hostname */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    ret = resolve_hostname(host, &addr);
    if (ret < 0) {
        printk(KERN_ERR "kwebdavfs: failed to resolve %s: %d\n", host, ret);
        goto cleanup_sock;
    }

    do {
        ret = kernel_connect(sock, (struct sockaddr *)&addr, sizeof(addr), 0);
    } while ((ret == -ERESTARTSYS || ret == -EINTR) && !fatal_signal_pending(current));
    if (ret < 0) {
        printk(KERN_ERR "kwebdavfs: connect to %s:%d failed: %d\n", host, port, ret);
        goto cleanup_sock;
    }

    /* TLS handshake for HTTPS */
    if (use_ssl) {
        ret = upgrade_to_tls(sock, host, &tls);
        if (ret < 0) {
            printk(KERN_ERR "kwebdavfs: TLS handshake to %s failed: %d\n", host, ret);
            goto cleanup_sock;
        }
    }

    /* Build and send request */
    req.method     = webdav_method_names[method];
    req.url        = (char *)url;
    req.host       = host;
    req.path       = path;
    req.body       = (char *)body;
    req.body_len   = body_len;
    if (fsi->username && fsi->password)
        req.auth_header = build_auth_header(fsi->username, fsi->password);

    ret = send_http_request(sock, tls, &req);
    if (ret < 0) {
        printk(KERN_ERR "kwebdavfs: send request failed: %d\n", ret);
        goto cleanup_auth;
    }

    ret = receive_http_response(sock, tls, response);
    if (ret < 0) {
        printk(KERN_ERR "kwebdavfs: receive response failed: %d\n", ret);
        goto cleanup_auth;
    }

    printk(KERN_DEBUG "kwebdavfs: %s %s -> %d (%s)\n",
           req.method, url, response->status_code,
           use_ssl ? "TLS1.3" : "plain");

cleanup_auth:
    kfree(req.auth_header);
    if (tls) tls13_free(tls);
cleanup_sock:
    sock_release(sock);
cleanup_url:
    kfree(host);
    kfree(path);
    return ret;
}

/**
 * kwebdavfs_http_move - send a WebDAV MOVE request.
 *
 * @overwrite: if true, send "Overwrite: T" (replace existing destination).
 * Returns 0 on success, negative errno on failure.
 */
int kwebdavfs_http_move(struct kwebdavfs_fs_info *fsi, const char *src_url,
                        const char *dst_url, bool overwrite)
{
    struct socket     *sock = NULL;
    struct tls13_ctx  *tls  = NULL;
    struct sockaddr_in addr;
    struct http_request req;
    struct webdav_response response;
    char *host, *path, *extra;
    int  port, ret;
    bool use_ssl;

    memset(&req, 0, sizeof(req));
    memset(&response, 0, sizeof(response));

    ret = parse_url(src_url, &host, &path, &port, &use_ssl);
    if (ret < 0)
        return ret;

    extra = kasprintf(GFP_KERNEL, "Destination: %s\r\nOverwrite: %s\r\n",
                      dst_url, overwrite ? "T" : "F");
    if (!extra) { ret = -ENOMEM; goto cleanup_url; }

    ret = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
    if (ret < 0) goto cleanup_extra;

    sock->sk->sk_rcvtimeo = msecs_to_jiffies(30000);
    sock->sk->sk_sndtimeo = msecs_to_jiffies(30000);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    ret = resolve_hostname(host, &addr);
    if (ret < 0) goto cleanup_sock;

    do {
        ret = kernel_connect(sock, (struct sockaddr *)&addr, sizeof(addr), 0);
    } while ((ret == -ERESTARTSYS || ret == -EINTR) && !fatal_signal_pending(current));
    if (ret < 0) goto cleanup_sock;

    if (use_ssl) {
        ret = upgrade_to_tls(sock, host, &tls);
        if (ret < 0) goto cleanup_sock;
    }

    req.method        = "MOVE";
    req.url           = (char *)src_url;
    req.host          = host;
    req.path          = path;
    req.extra_headers = extra;
    if (fsi->username && fsi->password)
        req.auth_header = build_auth_header(fsi->username, fsi->password);

    ret = send_http_request(sock, tls, &req);
    if (ret < 0) goto cleanup_auth;

    ret = receive_http_response(sock, tls, &response);
    if (ret < 0) goto cleanup_auth;

    /* 201 Created or 204 No Content = success */
    if (response.status_code != 201 && response.status_code != 204) {
        printk(KERN_ERR "kwebdavfs: MOVE %s -> %s returned %d\n",
               src_url, dst_url, response.status_code);
        ret = (response.status_code == 412) ? -EEXIST : -EIO;
    }

cleanup_auth:
    kfree(req.auth_header);
    kwebdavfs_free_response(&response);
    if (tls) tls13_free(tls);
cleanup_sock:
    sock_release(sock);
cleanup_extra:
    kfree(extra);
cleanup_url:
    kfree(host);
    kfree(path);
    return ret;
}

int kwebdavfs_propfind(struct kwebdavfs_fs_info *fsi, const char *url,
                      struct list_head *entries)
{
    struct webdav_response response;
    const char *propfind_body = 
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "<D:propfind xmlns:D=\"DAV:\">"
        "<D:prop>"
        "<D:resourcetype/>"
        "<D:getcontentlength/>"
        "<D:getlastmodified/>"
        "<D:getetag/>"
        "</D:prop>"
        "</D:propfind>";
    int ret;
    
    INIT_LIST_HEAD(entries);
    
    ret = kwebdavfs_http_request(fsi, WEBDAV_PROPFIND, url, propfind_body, 
                                strlen(propfind_body), &response);
    if (ret < 0)
        return ret;
        
    if (response.status_code != 207) {
        kwebdavfs_free_response(&response);
        return -EIO;
    }
    
    /* Parse XML response */
    if (response.data) {
        ret = kwebdavfs_parse_xml_response(response.data, url, entries);
    }
    
    kwebdavfs_free_response(&response);
    return ret;
}

/* Find close-tag that ends with :local_name> e.g. </d:response> */
static const char *find_close_tag(const char *p, const char *local_name)
{
    size_t llen = strlen(local_name);
    while (*p) {
        const char *lt = strchr(p, '<');
        if (!lt) break;
        if (lt[1] == '/') {
            /* < / ns : name > or < / name > */
            const char *colon = strchr(lt + 2, ':');
            const char *gt    = strchr(lt + 2, '>');
            if (!gt) break;
            const char *name_start = colon ? colon + 1 : lt + 2;
            if ((size_t)(gt - name_start) == llen &&
                memcmp(name_start, local_name, llen) == 0)
                return lt;
        }
        p = lt + 1;
    }
    return NULL;
}

/* Find open-tag content for element with given local name; returns ptr
 * to char after '>', sets *end to start of close tag */
static const char *find_element(const char *p, const char *local_name,
                                 const char **end_tag)
{
    size_t llen = strlen(local_name);
    while (*p) {
        const char *lt = strchr(p, '<');
        if (!lt) break;
        if (lt[1] != '/') {
            /* skip ahead past namespace prefix if any */
            const char *colon = strchr(lt + 1, ':');
            const char *gt    = strchr(lt + 1, '>');
            if (!gt) break;
            const char *name_start = colon ? colon + 1 : lt + 1;
            /* Name ends at '>' or space or '/' */
            size_t nlen = gt - name_start;
            const char *sp = memchr(name_start, ' ', nlen);
            const char *sl = memchr(name_start, '/', nlen);
            if (sp && sp < name_start + nlen) nlen = sp - name_start;
            if (sl && sl < name_start + nlen) nlen = sl - name_start;
            if (nlen == llen && memcmp(name_start, local_name, llen) == 0) {
                const char *content = gt + 1;
                *end_tag = find_close_tag(content, local_name);
                return content;
            }
        }
        p = lt + 1;
    }
    return NULL;
}

/* Decode percent-encoded URL in-place (e.g. %20 -> space, %c3%a6 -> UTF-8 byte) */
static void url_decode_inplace(char *str)
{
    char *src = str, *dst = str;
    int d1, d2;

    while (*src) {
        if (*src == '%' && (d1 = hex_to_bin((unsigned char)src[1])) >= 0 &&
                           (d2 = hex_to_bin((unsigned char)src[2])) >= 0) {
            *dst++ = (char)((d1 << 4) | d2);
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

int kwebdavfs_parse_xml_response(const char *xml, const char *request_url,
                                  struct list_head *entries)
{
    struct webdav_dirent *entry;
    const char *p = xml;
    const char *resp_end;
    const char *resp_content;
    int count = 0;

    printk(KERN_INFO "kwebdavfs: parsing XML (%zu bytes): %.120s...\n",
           strlen(xml), xml);

    /* Iterate over <response> elements */
    while ((resp_content = find_element(p, "response", &resp_end)) != NULL) {
        const char *href_end;
        const char *href_content;

        /* Find href within this response */
        href_content = find_element(resp_content, "href", &href_end);
        if (!href_content || !href_end || href_end > resp_end)
            goto next_resp;

        entry = kzalloc(sizeof(*entry), GFP_KERNEL);
        if (!entry)
            break;

        /* Store href */
        {
            size_t hlen = href_end - href_content;
            entry->href = kmalloc(hlen + 1, GFP_KERNEL);
            if (entry->href) {
                memcpy(entry->href, href_content, hlen);
                entry->href[hlen] = '\0';
            }
        }

        /* Skip self-reference (the collection itself) */
        if (entry->href && request_url) {
            size_t url_len  = strlen(request_url);
            size_t href_len = strlen(entry->href);
            if (href_len > 0 && href_len <= url_len &&
                strcmp(request_url + url_len - href_len, entry->href) == 0) {
                kfree(entry->href);
                kfree(entry);
                goto next_resp;
            }
        }

        /* Extract filename from path */
        if (entry->href) {
            char *last_slash = strrchr(entry->href, '/');
            if (last_slash && *(last_slash + 1) != '\0') {
                entry->name = kstrdup(last_slash + 1, GFP_KERNEL);
            } else if (last_slash) {
                /* directory: ends with / */
                *last_slash = '\0';
                char *prev_slash = strrchr(entry->href, '/');
                entry->name = prev_slash ? kstrdup(prev_slash + 1, GFP_KERNEL)
                                         : kstrdup(entry->href, GFP_KERNEL);
                *last_slash = '/';
            }
            if (!entry->name)
                entry->name = kstrdup("unknown", GFP_KERNEL);
            /* URL-decode the name (e.g. %20 -> space, %c3%a6 -> UTF-8) */
            if (entry->name)
                url_decode_inplace(entry->name);
        }

        /* Check if directory: look for <collection/> or <collection> */
        if (strnstr(resp_content, "collection", resp_end - resp_content))
            entry->is_dir = true;

        /* Extract content length */
        {
            const char *cl_end;
            const char *cl = find_element(resp_content, "getcontentlength", &cl_end);
            if (cl && cl_end && cl < resp_end)
                entry->size = simple_strtoll(cl, NULL, 10);
        }

        ktime_get_real_ts64(&entry->mtime);
        list_add_tail(&entry->list, entries);
        count++;

next_resp:
        p = resp_end ? resp_end + 1 : resp_content + 1;
    }

    printk(KERN_INFO "kwebdavfs: parsed %d entries\n", count);
    return 0;
}

void kwebdavfs_free_dirents(struct list_head *entries)
{
    struct webdav_dirent *entry, *tmp;
    
    list_for_each_entry_safe(entry, tmp, entries, list) {
        list_del(&entry->list);
        kfree(entry->name);
        kfree(entry->href);
        kfree(entry->etag);
        kfree(entry);
    }
}

void kwebdavfs_free_response(struct webdav_response *response)
{
    if (response) {
        kvfree(response->data); /* may be vmalloc-backed for large bodies */
        kfree(response->etag);
        memset(response, 0, sizeof(*response));
    }
}