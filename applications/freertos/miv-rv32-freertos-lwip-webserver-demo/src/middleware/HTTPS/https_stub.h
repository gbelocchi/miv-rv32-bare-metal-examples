#ifndef HTTPS_STUB_H
#define HTTPS_STUB_H

#include "lwip/api.h"

void https_init(void);
err_t https_server_accept(struct netconn *conn);
err_t https_read(struct netconn *conn, struct netbuf **buf, void **data, u16_t *len);
err_t https_write(struct netconn *conn, const void *data, u16_t len);

#endif /* HTTPS_STUB_H */
