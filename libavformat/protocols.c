/*
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "config.h"

#include "libavutil/avstring.h"
#include "libavutil/mem.h"

#include "url.h"

extern const URLProtocol ff_async_protocol;
extern const URLProtocol ff_bluray_protocol;
extern const URLProtocol ff_cache_protocol;
extern const URLProtocol ff_concat_protocol;
extern const URLProtocol ff_crypto_protocol;
extern const URLProtocol ff_data_protocol;
extern const URLProtocol ff_ffrtmpcrypt_protocol;
extern const URLProtocol ff_ffrtmphttp_protocol;
extern const URLProtocol ff_file_protocol;
extern const URLProtocol ff_ftp_protocol;
extern const URLProtocol ff_gopher_protocol;
extern const URLProtocol ff_hls_protocol;
extern const URLProtocol ff_http_protocol;
extern const URLProtocol ff_httpproxy_protocol;
extern const URLProtocol ff_https_protocol;
extern const URLProtocol ff_icecast_protocol;
extern const URLProtocol ff_mmsh_protocol;
extern const URLProtocol ff_mmst_protocol;
extern const URLProtocol ff_md5_protocol;
extern const URLProtocol ff_pipe_protocol;
extern const URLProtocol ff_prompeg_protocol;
extern const URLProtocol ff_rtmp_protocol;
extern const URLProtocol ff_rtmpe_protocol;
extern const URLProtocol ff_rtmps_protocol;
extern const URLProtocol ff_rtmpt_protocol;
extern const URLProtocol ff_rtmpte_protocol;
extern const URLProtocol ff_rtmpts_protocol;
extern const URLProtocol ff_rtp_protocol;
extern const URLProtocol ff_sctp_protocol;
extern const URLProtocol ff_srtp_protocol;
extern const URLProtocol ff_subfile_protocol;
extern const URLProtocol ff_tee_protocol;
extern const URLProtocol ff_tcp_protocol;
extern const URLProtocol ff_tls_gnutls_protocol;
extern const URLProtocol ff_tls_schannel_protocol;
extern const URLProtocol ff_tls_securetransport_protocol;
extern const URLProtocol ff_tls_openssl_protocol;
extern const URLProtocol ff_udp_protocol;
extern const URLProtocol ff_udplite_protocol;
extern const URLProtocol ff_unix_protocol;
extern const URLProtocol ff_librtmp_protocol;
extern const URLProtocol ff_librtmpe_protocol;
extern const URLProtocol ff_librtmps_protocol;
extern const URLProtocol ff_librtmpt_protocol;
extern const URLProtocol ff_librtmpte_protocol;
extern const URLProtocol ff_libssh_protocol;
extern const URLProtocol ff_libsmbclient_protocol;
extern const URLProtocol ff_fd_protocol;


#include "libavutil/opt.h"
#include "unistd.h"

static const AVOption fd_options[] = {
        {NULL}
};

static const AVClass fd_class = {
        .class_name = "fd",
        .item_name  = av_default_item_name,
        .option     = fd_options,
        .version    = LIBAVUTIL_VERSION_INT,
};

typedef struct FDContext {
    const AVClass *class;
    int fd;
    int trunc;
    int blocksize;
    int follow;
} FDContext;

static int fd_open(URLContext *h, const char *url, int flags) {
    printf("-------------------fd_open: %s\n",url);
    FDContext *c = h->priv_data;

    //
    av_strstart(url, "fd://", &url);

    char *final;
    int fd = strtol(url, &final, 10);
    printf("-------------------fd_open: %d\n",fd);

    if ((url == final) || *final) {/* No digits found, or something like 10ab */
        if (flags & AVIO_FLAG_WRITE) {
            fd = 1;
        } else {
            fd = 0;
        }
    }

    c->fd = fd;
    h->is_streamed = 1;
    return 0;
}

static int fd_read(URLContext *h, unsigned char *buf, int size) {
    FDContext *c = h->priv_data;
    int ret = read(c->fd, buf, size);
    return ret < 0 ? AVERROR(errno) : ret;
}

static int fd_write(URLContext *h, const unsigned char *buf, int size) {
    FDContext *c = h->priv_data;
    int ret = write(c->fd, buf, size);
    return ret < 0 ? AVERROR(errno) : ret;
}

static int fd_close(URLContext *h) {
    FDContext *c = h->priv_data;
    return close(c->fd);
}

static int fd_get_file_handle(URLContext *h) {
    FDContext *c = h->priv_data;
    return c->fd;
}


const URLProtocol ff_fd_protocol = {
        .name                = "fd",
        .url_open            = fd_open,
        .url_read            = fd_read,
        .url_write           = fd_write,
        .url_close           = fd_close,
        .url_get_file_handle = fd_get_file_handle,
        .priv_data_size      = sizeof(FDContext),
        .priv_data_class     = &fd_class,
        .flags               = URL_PROTOCOL_FLAG_NETWORK,
};

#include "libavformat/protocol_list.c"

const AVClass *ff_urlcontext_child_class_next(const AVClass *prev) {
    int i;

    /* find the protocol that corresponds to prev */
    for (i = 0; prev && url_protocols[i]; i++) {
        if (url_protocols[i]->priv_data_class == prev) {
            i++;
            break;
        }
    }

    /* find next protocol with priv options */
    for (; url_protocols[i]; i++)
        if (url_protocols[i]->priv_data_class)
            return url_protocols[i]->priv_data_class;
    return NULL;
}


const char *avio_enum_protocols(void **opaque, int output) {
    const URLProtocol **p = *opaque;

    p = p ? p + 1 : url_protocols;
    *opaque = p;
    if (!*p) {
        *opaque = NULL;
        return NULL;
    }
    if ((output && (*p)->url_write) || (!output && (*p)->url_read))
        return (*p)->name;
    return avio_enum_protocols(opaque, output);
}

const URLProtocol **ffurl_get_protocols(const char *whitelist,
                                        const char *blacklist) {
    const URLProtocol **ret;
    int i, ret_idx = 0;

    ret = av_mallocz_array(FF_ARRAY_ELEMS(url_protocols), sizeof(*ret));
    if (!ret)
        return NULL;

    for (i = 0; url_protocols[i]; i++) {
        const URLProtocol *up = url_protocols[i];

        if (whitelist && *whitelist && !av_match_name(up->name, whitelist))
            continue;
        if (blacklist && *blacklist && av_match_name(up->name, blacklist))
            continue;

        ret[ret_idx++] = up;
    }

    return ret;
}
