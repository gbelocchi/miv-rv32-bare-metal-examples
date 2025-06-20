#include "https_stub.h"
#include "lwip/mem.h"
#include <string.h>

#define HTTPS_KEY 0xAA

void https_init(void) {}

err_t https_server_accept(struct netconn *conn)
{
    struct netbuf *buf;
    char *data;
    u16_t len;
    err_t err = netconn_recv(conn, &buf);
    if (err != ERR_OK)
        return err;
    netbuf_data(buf, (void **)&data, &len);
    if (len < 5 || strncmp(data, "HELLO", 5) != 0)
    {
        netbuf_delete(buf);
        return ERR_CLSD;
    }
    netbuf_delete(buf);
    netconn_write(conn, "WORLD", 5, NETCONN_NOCOPY);
    return ERR_OK;
}

static void xor_buf(void *d, u16_t len)
{
    u8_t *p = (u8_t *)d;
    while (len--)
    {
        *p++ ^= HTTPS_KEY;
    }
}

err_t https_read(struct netconn *conn, struct netbuf **buf, void **data, u16_t *len)
{
    err_t err = netconn_recv(conn, buf);
    if (err != ERR_OK)
        return err;
    netbuf_data(*buf, data, len);
    xor_buf(*data, *len);
    return ERR_OK;
}

err_t https_write(struct netconn *conn, const void *data, u16_t len)
{
    void *tmp = mem_malloc(len);
    if (!tmp)
        return ERR_MEM;
    MEMCPY(tmp, data, len);
    xor_buf(tmp, len);
    err_t err = netconn_write(conn, tmp, len, NETCONN_COPY);
    mem_free(tmp);
    return err;
}
