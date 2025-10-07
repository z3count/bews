#ifndef BEWS_H
#define BEWS_H

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "hash.h"
#include "tpool.h"

#define PATH_MAX 4096

#define ADDRFMT "%u.%u.%u.%u"
#define ADDRTOFMT(a)                                   \
        (a.s_addr & 0x000000ff),                       \
        (a.s_addr & 0x0000ff00) >> 8,                  \
        (a.s_addr & 0x00ff0000) >> 16,                 \
        (a.s_addr& 0xff000000) >> 24

enum http_version {
        HTTP_10,
        HTTP_11,
};




enum method_type {
        GET,
        PUT,
        POST,
        HEAD,
        DELETE,
        CONNECT,
        OPTIONS,
        TRACE,
        N_METHODS,
};

struct method {
        enum method_type id;
        char *str;
        size_t len;
};

enum {
        ACCEPT,
        ACCEPT_CHARSET,
        ACCEPT_ENCODING,
        ACCEPT_LANGUAGE,
        ACCEPT_RANGE,
        AGE,
        ALLOW,
        AUTHORIZATION,
        CACHE_CONTROL,
        CONNECTION,
        CONTENT,
        CONTENT_ENCODING,
        CONTENT_LANGUAGE,
        CONTENT_LENGTH,
        CONTENT_LOCATION,
        CONTENT_MD5,
        CONTENT_RANGE,
        CONTENT_TYPE,
        COOKIE,
        DATE,
        DNT,
        ETAG,
        EXPECTS,
        EXPIRE,
        FROM,
        HOST,
        IF_MATCH,
        IF_MODIFIED_SINCE,
        IF_NONE_MATCH,
        IF_RANGE,
        IF_UNMODIFIED_SINCE,
        KEEP_ALIVE,
        LAST_MODIFIED,
        LOCATION,
        MAX_FORWARDS,
        PRAGMA,
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        RANGE,
        REFERER,
        RETRY_AFTER,
        SERVER,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        UPGRADE,
        USER_AGENT,
        VARY,
        VIA,
        WARNING,
        WWW_AUTHENTICATE,
        X_FORWARDED_FOR,

        HEADER_FIELD_NB,
};

enum uri_type {
        URI_TYPE_STAR,
        URI_TYPE_ABSOLUTE_URI,
        URI_TYPE_ABSOLUTE_PATH,
        URI_TYPE_AUTHORITY,
};

enum code {
        CODE_100 = 0,
        CODE_101,

        CODE_200,
        CODE_201,
        CODE_202,
        CODE_203,
        CODE_204,
        CODE_205,
        CODE_206,

        CODE_300,
        CODE_301,
        CODE_302,
        CODE_303,
        CODE_304,
        CODE_305,
        CODE_306,
        CODE_307,

        CODE_400,
        CODE_401,
        CODE_402,
        CODE_403,
        CODE_404,
        CODE_405,
        CODE_406,
        CODE_407,
        CODE_408,
        CODE_409,
        CODE_410,
        CODE_411,
        CODE_412,
        CODE_413,
        CODE_414,
        CODE_415,
        CODE_416,
        CODE_417,

        CODE_500,
        CODE_501,
        CODE_502,
        CODE_503,
        CODE_504,
        CODE_505,

        CODE_NB,
};

enum content_flag {
        BEWS_CONTENT_FLAG_MMAPED    = (1u << 0),
        BEWS_CONTENT_FLAG_ALLOCATED = (1u << 1),
};


struct code_hdl {
        char *msg;
        int code;
        enum code idx;
};


struct request_uri {
        enum uri_type type;;         /* absolute, *, path, ... */
        char *value;
        size_t value_len;
        char *path;
        char on_disk[PATH_MAX];
        size_t path_len;
        struct stat st;               /* path attributes */
};

struct bews_ctx;

struct request {
        ttask task;                    /* mandatory */

        struct bews_ctx *shared;
        int fd;

        struct in_addr c_addr;

        enum method_type method;      /* GET, POST, PUT, CONNECT, ... */
        struct request_uri uri;
        enum http_version version;    /* 1.0 or 1.1 */
        struct code_hdl *hint;
        char *host;
        char *referer;
        char *user_agent;

        char *reqbuf;
        size_t reqbuf_len;

        char *field[HEADER_FIELD_NB];
};


typedef int (* tbews_response_get_func)(struct request *);
typedef int (* tbews_response_put_func)(struct request *);
typedef int (* tbews_response_post_func)(struct request *);
typedef int (* tbews_response_head_func)(struct request *);
typedef int (* tbews_response_delete_func)(struct request *);
typedef int (* tbews_response_connect_func)(struct request *);
typedef int (* tbews_response_options_func)(struct request *);
typedef int (* tbews_response_trace_func)(struct request *);

struct driver {
        tbews_response_get_func get;
        tbews_response_put_func put;
        tbews_response_post_func post;
        tbews_response_head_func head;
        tbews_response_delete_func delete;
        tbews_response_connect_func connect;
        tbews_response_options_func options;
        tbews_response_trace_func trace;
};

struct bews_ctx {
        struct driver driver;

        pthread_mutex_t lock;
        int lock_inited;

#define BEWS_DEFAULT_USER_NAME "www-data"
        char *user_name;

#define BEWS_DEFAULT_PORT 80
        uint16_t port;

#define BEWS_DEFAULT_ROOT_DIR "/usr/local/var/www"
        char *root_dir;

        struct code_hdl *codes;
        thash *h; /* addresses/fd association */

        int server_fd;
};

struct bews_ctx * bews_ctx_new(void);
void bews_ctx_free(struct bews_ctx *ctx);

void methods_init(void);
void request_field_init(void);

int bews_set_path_from_uri(struct request *req);
int bews_set_code_from_path(struct request *req, enum code *codep);
void bews_url_dummy_decode(char *dest, const char * const src);

int do_parse_request_field(struct request *req, char *buf, size_t buf_len);
int do_parse_request_line(struct request *req, char *buf, size_t buf_len, size_t *request_lenp);
int do_handle_request(struct request *req);


#endif /* BEWS_H */
