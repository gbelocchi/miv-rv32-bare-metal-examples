#include "https_tls.h"
#include "lwip/mem.h"
#include <string.h>

#include "mbedtls/ssl.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"

static mbedtls_ssl_config conf;
static mbedtls_x509_crt srvcert;
static mbedtls_pk_context pkey;
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_ssl_context ssl;

static int lwip_send(void *ctx, const unsigned char *buf, size_t len)
{
    struct netconn *conn = (struct netconn *)ctx;
    err_t err = netconn_write(conn, buf, len, NETCONN_COPY);
    if (err != ERR_OK)
        return MBEDTLS_ERR_NET_SEND_FAILED;
    return len;
}

static int lwip_recv(void *ctx, unsigned char *buf, size_t len)
{
    struct netconn *conn = (struct netconn *)ctx;
    struct netbuf *nb;
    void *data;
    u16_t blen;
    err_t err = netconn_recv(conn, &nb);
    if (err != ERR_OK)
        return MBEDTLS_ERR_NET_RECV_FAILED;
    netbuf_data(nb, &data, &blen);
    if (blen > len)
        blen = len;
    MEMCPY(buf, data, blen);
    netbuf_delete(nb);
    return blen;
}

void https_init(void)
{
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    const char *pers = "webserver";
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                          (const unsigned char *)pers, strlen(pers));

    mbedtls_x509_crt_parse(&srvcert,
                           (const unsigned char *)mbedtls_test_srv_crt,
                           mbedtls_test_srv_crt_len);
    mbedtls_pk_parse_key(&pkey,
                         (const unsigned char *)mbedtls_test_srv_key,
                         mbedtls_test_srv_key_len,
                         NULL,
                         0);

    mbedtls_ssl_config_defaults(&conf,
                                MBEDTLS_SSL_IS_SERVER,
                                MBEDTLS_SSL_TRANSPORT_STREAM,
                                MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, NULL);
    mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey);
}

err_t https_server_accept(struct netconn *conn)
{
    mbedtls_ssl_init(&ssl);
    if (mbedtls_ssl_setup(&ssl, &conf) != 0)
        return ERR_CLSD;
    mbedtls_ssl_set_bio(&ssl, conn, lwip_send, lwip_recv, NULL);

    int ret;
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            return ERR_CLSD;
        }
    }
    return ERR_OK;
}

err_t https_read(struct netconn *conn, struct netbuf **buf, void **data, u16_t *len)
{
    (void)conn;
    unsigned char tmp[512];
    int ret = mbedtls_ssl_read(&ssl, tmp, sizeof(tmp));
    if (ret <= 0)
        return ERR_CLSD;

    *buf = netbuf_new();
    if (!*buf)
        return ERR_MEM;
    *data = netbuf_alloc(*buf, ret);
    if (!*data)
    {
        netbuf_delete(*buf);
        return ERR_MEM;
    }
    MEMCPY(*data, tmp, ret);
    *len = (u16_t)ret;
    return ERR_OK;
}

err_t https_write(struct netconn *conn, const void *data, u16_t len)
{
    (void)conn;
    int ret = mbedtls_ssl_write(&ssl, data, len);
    return (ret > 0) ? ERR_OK : ERR_CLSD;
}
