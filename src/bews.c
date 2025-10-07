#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <dirent.h>
#include <time.h>
#include <math.h>
#include <assert.h>

#include "bews.h"
#include "main.h"
#include "log.h"
#include "utils.h"
#include "list.h"

struct method methods[] = {
#define MAP(x) { .id = x, .str = #x, .len = 0 }
        MAP(GET),
        MAP(PUT),
        MAP(POST),
        MAP(HEAD),
        MAP(DELETE),
        MAP(CONNECT),
        MAP(OPTIONS),
        MAP(TRACE),
#undef MAP
};

static struct {
        int id;
        char *name;
        size_t len;
} field_name[HEADER_FIELD_NB] = {
        { ACCEPT, "Accept", 0 },
        { ACCEPT_CHARSET, "Accept-Charset", 0 },
        { ACCEPT_ENCODING, "Accept-Encoding", 0 },
        { ACCEPT_LANGUAGE, "Accept-Language", 0 },
        { ACCEPT_RANGE, "Accept-Range", 0 },
        { AGE, "Age", 0 },
        { ALLOW, "Allow", 0 },
        { AUTHORIZATION, "Authorization", 0 },
        { CACHE_CONTROL, "Cache-Control", 0 },
        { CONNECTION, "Connection", 0 },
        { CONTENT, "Content", 0 },
        { CONTENT_ENCODING, "Content-Encoding", 0 },
        { CONTENT_LANGUAGE, "Content-Language", 0 },
        { CONTENT_LENGTH, "Content-Length", 0 },
        { CONTENT_LOCATION, "Content-Location", 0 },
        { CONTENT_MD5, "Content-MD5", 0 },
        { CONTENT_RANGE, "Content-Range", 0 },
        { CONTENT_TYPE, "Content-Type", 0 },
        { COOKIE, "Cookie", 0 },
        { DATE, "Date", 0 },
        { DNT, "DNT", 0},
        { ETAG, "ETag", 0 },
        { EXPECTS, "Expect", 0 },
        { EXPIRE, "Expire", 0 },
        { FROM, "From", 0 },
        { HOST, "Host", 0 },
        { IF_MATCH, "If-Match", 0 },
        { IF_MODIFIED_SINCE, "If-Modified-Since", 0 },
        { IF_NONE_MATCH, "If-None-Match", 0 },
        { IF_RANGE, "If-Range", 0 },
        { IF_UNMODIFIED_SINCE, "IF-Unmodified-Since", 0 },
        { KEEP_ALIVE, "Keep-Alive", 0 },
        { LAST_MODIFIED, "Last-Modified", 0 },
        { LOCATION, "Location", 0 },
        { MAX_FORWARDS, "Max-Forwards", 0 },
        { PRAGMA, "Pragma", 0 },
        { PROXY_AUTHENTICATE, "Proxy-Authenticate", 0 },
        { PROXY_AUTHORIZATION, "Proxy-Authorization", 0 },
        { RANGE, "Range", 0 },
        { REFERER, "Referer", 0 },
        { RETRY_AFTER, "Retry-After", 0 },
        { SERVER, "Server", 0 },
        { TE, "TE", 0 },
        { TRAILER, "Trailer", 0 },
        { TRANSFER_ENCODING, "Transfer-Encoding", 0 },
        { UPGRADE, "Upgrade", 0 },
        { USER_AGENT, "User-Agent", 0 },
        { VARY, "Vary", 0 },
        { VIA, "Via", 0 },
        { WARNING, "Warning", 0 },
        { WWW_AUTHENTICATE, "WWW-Authenticate", 0 },
        { X_FORWARDED_FOR, "X-Forwarded-For", 0 },
};

struct code_hdl codes[CODE_NB] = {
#define M(c, msg) { msg, c, CODE_##c }
        M(100, "Continue"),
        M(101, "Switching Protocols"),

        M(200, "OK"),
        M(201, "Created"),
        M(202, "Accepted"),
        M(203, "Non-Authoritative Information"),
        M(204, "No Content"),
        M(205, "Reset Content"),
        M(206, "Partial Content"),

        M(300, "Multiple Choices"),
        M(301, "Moved Permanently"),
        M(302, "Found"),
        M(303, "See Other"),
        M(304, "Not Modified"),
        M(305, "Use Proxy"),
        M(306, "(Unused)"),
        M(307, "Temporary Redirect"),

        M(400, "Bad Request"),
        M(401, "Unauthorized"),
        M(402, "Payment Required"),
        M(403, "Forbidden"),
        M(404, "Not Found"),
        M(405, "Method Not Allowed"),
        M(406, "Not Acceptable"),
        M(407, "Proxy Authentication Required"),
        M(408, "Request Timeout"),
        M(409, "Conflict"),
        M(410, "Gone"),
        M(411, "Length Required"),
        M(412, "Precondition Failed"),
        M(413, "Request Entity Too Large"),
        M(414, "Request-URI too Long"),
        M(415, "Unsupported Media Type"),
        M(416, "Requested Range Not Satisfiable"),
        M(417, "Expectation Failed"),

        M(500, "Internal Server Error"),
        M(501, "Not Implemented"),
        M(502, "Bad Gateway"),
        M(503, "Service Unavailable"),
        M(504, "Gateway Timeout"),
        M(505, "HTTP Version Not Supported"),
#undef M
};

static int bews_send_buffer(int fd, char *buf, size_t buf_len)
{
        int remain;
        int r = -1;
        int cc;

        if ((remain = buf_len) < 0) {
                 /* sanity check */
                log(0, "invalid buffer size: %zu", buf_len);
                goto end;
        }

        while (remain > 0) {
          again:
                cc = send(fd, buf, remain, MSG_DONTWAIT|MSG_NOSIGNAL);
                if (-1 == cc) {
                        if (EAGAIN == errno || EINTR == errno)
                                goto again;

                        if (EPIPE == errno) {
                                r = 0; /* Ignore this */
                        } else {
                                log(0, "send: %m");
                        }
                        goto end;
                }

                buf += cc;
                remain -= cc;
        }

        r = 0;
  end:
        log(2, "ret=%d", r);
        return r;
}

static void bews_send_header(struct request *req, enum code code,
                             size_t data_len)
{
        char header[4096] = "";
        char timebuf[128] = "";
        size_t header_len;
        time_t t;
        struct tm *tmp = NULL;
        struct bews_ctx *ctx = req->shared;

        t = time(NULL);
        if (NULL == (tmp = localtime(&t))) {
                log(0, "localtime: %m");
                exit(EXIT_FAILURE);
        }

        if (0 == strftime(timebuf, sizeof timebuf,
                          "Last-Modified: %a, %d %b %Y %H:%M:%S GMT\r\n", tmp)) {
                /* we don't exit the function, because it's not that horrible
                 * if the header field is empty */
                log(0, "strftime: %m");
                timebuf[0] = '\0';
        }

        switch ((int) code) {
        case CODE_301:
                if (esnprintf(header_len, header, sizeof header,
                              "HTTP/1.1 %d %s\r\n"
                              "Location: http://%s/%s/\r\n"
                              "Content-Length: 0\r\n"
                              "\r\n",
                              ctx->codes[code].code,
                              ctx->codes[code].msg,
                              req->host,
                              req->uri.path))
                        log(0, "Truncated header.");
                break;

        default:
                if (esnprintf(header_len, header, sizeof header,
                              "HTTP/1.1 %d %s\r\n"
                              "Content-Length: %zu\r\n"
                              "%s"
                              "\r\n",
                              ctx->codes[code].code,
                              ctx->codes[code].msg,
                              data_len,
                              timebuf))
                        log(0, "Truncated header.");
        }

        if (header_len >= sizeof header)
                log(0, "Truncated output.");

        if (bews_send_buffer(req->fd, header, header_len) < 0) {
                log(0, "send header failed");
                /* XXX: deal with it... */
        }
}

static void bews_send_content(struct request *req, char *buf, size_t buf_len,
                              enum content_flag flag)
{
        void *addr = buf;

        if (bews_send_buffer(req->fd, buf, buf_len) < 0) {
                log(0, "send content failed");
                /* XXX: deal with it... */
        }

        if (flag & BEWS_CONTENT_FLAG_MMAPED)
                (void) munmap(addr, buf_len);

        if (flag & BEWS_CONTENT_FLAG_ALLOCATED)
                /* addr is the backup of the original buf's value */
                free(addr);
}

int bews_set_path_from_uri(struct request *req)
{
        int r = -1;
        char *reqbuf = req->uri.value;
        size_t reqbuf_len = req->uri.value_len;
        char *index = "index.html";
        size_t index_len = strlen(index);
        char index_path[PATH_MAX];
        size_t index_path_len;
        char *p = NULL;

        if (! reqbuf)
                goto end;

        log(2, "uri %s", reqbuf);

        while ('/' == *reqbuf) {
                reqbuf++;
                reqbuf_len--;
        }

        /* "GET  HTTP/1.1" -> we implicitely want / */
        if (0 == *reqbuf) {
                if (NULL == (req->uri.path = strdup(index))) {
                        log(0, "strdup: %m");
                        goto end;
                }
                req->uri.path_len = index_len;
                r = 0;
                goto end;
        }

        /* nothing but slashes? -> GET / */
        if (0 == reqbuf_len || ' ' == reqbuf[0]) {
                if (NULL == (req->uri.path = strdup(index))) {
                        log(0, "strdup: %m");
                        goto end;
                }
                req->uri.path_len = index_len;
                r = 0;
                goto end;
        }

        if ((p = strchr(reqbuf, ' ')))
                *p = 0;

        if (esnprintf(index_path_len, index_path, sizeof index_path,
                      "%sindex.html", reqbuf)) {
                log(0, "Truncated index file path");
                goto end;
        }

        if (access(index_path, F_OK) < 0) {
                if (NULL == (req->uri.path = strdup(reqbuf))) {
                        log(0, "strdup: %m");
                        goto end;
                }
                req->uri.path_len = reqbuf_len;
        } else {
                if (NULL == (req->uri.path = strdup(index_path))) {
                        log(0, "strdup: %m");
                        goto end;
                }
                req->uri.path_len = index_path_len;
        }

        r = 0;
  end:
        if (p)
                *p = ' ';

        log(2, "ret=%d path=%s", r, req->uri.path);
        return r;
}

/* XXX */
void bews_url_dummy_decode(char *dest, const char * const src)
{
        const char *p = src;
        char code[3] = "";
        unsigned long val = 0;

#define ISLEGIT(c) (('\0' != (c)) && isalnum((c)))

        while (*p) {
                if (('%' == *p) && ISLEGIT(p[1]) && ISLEGIT(p[2])) {
                        memcpy(code, ++p, 2);
                        val = strtoul(code, NULL, 16);
                        *dest++ = (char) val;
                        p += 2;
                } else {
                        *dest++ = *p++;
                }
        }

#undef ISLEGIT

        *dest = 0;
}


static int bews_set_full_path(char *dest, char *src)
{
        char tmpbuf[PATH_MAX] = "";
	int n = 0;
        int r = -1;

        bews_url_dummy_decode(tmpbuf, src);
        if ('\0' != tmpbuf[sizeof tmpbuf - 1]) {
                log(0, "Invalid request:  path too long");
                goto end;
        }

        if (esnprintf(n, dest, sizeof tmpbuf - 1, "%s", tmpbuf)) {
                log(0, "Truncated full path");
                goto end;
        }

        dest[n] = '\0';
        r = 0;
  end:
        return r;
}

int bews_set_code_from_path(struct request *req, enum code *codep)
{
        enum code code = 0u;
        int r = -1;
        struct request_uri *u = &req->uri;

        /* default value: we're ok! */
        code = CODE_200;
        memset(u->on_disk, 0, sizeof u->on_disk);

        if (bews_set_full_path(u->on_disk, u->path) < 0) {
                log(0, "Failed to set code from path");
                goto end;
        }

        if (stat(u->on_disk, &u->st) < 0) {
                switch (errno) {
                case ENOENT:
                        code = CODE_404;
                        break;
                case EACCES:
                        code = CODE_403;
                        break;
                default:
                        code = CODE_500;
                }

                log(2, "%s: %m", u->on_disk);
        }

        /* handle 301 redirect case... */
        if (S_ISDIR(u->st.st_mode))
                if ('/' != u->on_disk[strlen(u->on_disk) - 1])
                        code = CODE_301;

        r = 0;
  end:
        if (codep)
                *codep = code;

        log(2, "ret=%d", r);
        return r;
}

static int bews_permissions_to_str(mode_t mode, char **strp)
{
        char *str = NULL;
        char *base = "----------";
        int offset = 0;
        int r = -1;

        if (NULL == (str = strdup(base))) {
                log(0, "strdup: %m");
                goto end;
        }

        if (S_ISDIR(mode))
                str[offset] = 'd';

        offset++;
        if (mode & S_IRUSR)
                str[offset] = 'r';

        offset++;
        if (mode & S_IWUSR)
                str[offset] = 'w';

        offset++;
        if (mode & S_IXUSR)
                str[offset] = 'x';

        offset++;
        if (mode & S_IRGRP)
                str[offset] = 'r';

        offset++;
        if (mode & S_IWGRP)
                str[offset] = 'w';

        offset++;
        if (mode & S_IXGRP)
                str[offset] = 'x';

        offset++;
        if (mode & S_IROTH)
                str[offset] = 'r';

        offset++;
        if (mode & S_IWOTH)
                str[offset] = 'w';

        offset++;
        if (mode & S_IXOTH)
                str[offset] = 'x';

        r = 0;
  end:
        if (strp)
                *strp = str;

        return r;
}

static size_t bews_set_dir_entry(struct stat *stbuf, char *dir,
                                 char *entry_name, char *line, size_t line_len)
{
        size_t len = 0;
        char file[PATH_MAX];
        char timefmt[64];
        char sizefmt[32];
        struct tm *tm;
        int log_10 = 0;
        char offset[] = "           "; /* ugly hack, but hey... */
        char *perm = NULL;

        if (esnprintf(len, file, sizeof file, "%s/%s", dir, entry_name))
                log(0, "Truncated path.");

        if (stat(file, stbuf) < 0) {
                log(1, "stat(%s): %m", file);
                goto end;
        }

        if (NULL == (tm = localtime(&stbuf->st_mtime))) {
                log(1, "localtime: %m");
                /* skip this entry */
                if (esnprintf(len, timefmt, sizeof timefmt, "unknown"))
                        log(0, "Truncated time format.");
        } else {
                strftime(timefmt, sizeof timefmt, "%Y-%m-%d %H:%M", tm);
        }

        if (stbuf->st_size)
                log_10 = (int) (1 + floor(log10((double) stbuf->st_size)));
        else
                log_10 = 1;

        offset[strlen(offset) - log_10] = 0;
        if (esnprintf(len, sizefmt, sizeof sizefmt, "%zu",
                      stbuf->st_size))
                log(0, "Truncated size value.");

        if (bews_permissions_to_str(stbuf->st_mode, &perm) < 0)
                log(0, "%s: can't compute file permission", entry_name);

        if (esnprintf(len, line, line_len,
                      "%s %s %zu %s <a href=\"/%s/%s\">%s</a><br>\n",
                      perm ? perm : "unknown",
                      offset, stbuf->st_size, timefmt,
                      dir, entry_name, entry_name))
                log(0, "Truncated line entry.");

        free(perm);
  end:
        return len;
}

struct dir_conv {
        int n_dir_entries;
        int cursor;
        char **buf;
        size_t *buf_len;
        char p[1024];
        int error;
};

static void build_directory_buf_cb(void *elem, void *user_data)
{
        char *cur_name = elem;
        struct dir_conv *conv = user_data;
        struct stat stbuf;
        size_t tmp_len;
        char line[PATH_MAX];
        char *tmp = NULL;

        if (conv->cursor > conv->n_dir_entries)
                return;

        memset(&stbuf, 0, sizeof stbuf);

        if (0 == strcmp(cur_name, ".")) {
                conv->cursor++;
                return;
        }

        tmp_len = bews_set_dir_entry(&stbuf, conv->p, cur_name,
                                     line, sizeof line);

        if (NULL == (tmp = realloc(*conv->buf, *conv->buf_len + tmp_len))) {
                log(0, "realloc: %m");
                free(*conv->buf);
                *conv->buf = NULL;
                *conv->buf_len = 0;
                conv->error = -1;
        } else {
                *conv->buf = tmp;
                memcpy(*conv->buf + *conv->buf_len, line, tmp_len);
                *conv->buf_len += tmp_len;
        }

        conv->cursor++;
}

static int bews_set_content_dir(struct request *req, char **bufp,
                                size_t *buf_lenp, enum content_flag *flagp)
{
        int r = -1;
        char *buf = NULL;
        size_t buf_len = 0, plen = 0;
        enum content_flag flag = 0u;
        DIR *dir = NULL;
        struct dirent *ent;
        char prelude[256];
        size_t pre_len;
        char postlude[] = "</pre></small></body></html>\n";
        size_t post_len = sizeof postlude - 1;
        char p[1024];
        tlist *entry_list = NULL;
        char *tmp = NULL;

        log(2, "path=%s", req->uri.path);

        if (NULL == (dir = opendir(req->uri.path))) {
                log(0, "opendir(%s): %m", req->uri.path);
                goto end;
        }

        if (esnprintf(plen, p, sizeof p, "%s", req->uri.path))
                log(0, "Truncated URI.");

        if ('/' == p[strlen(p) - 1])
                p[strlen(p) - 1] = 0;

        if (esnprintf(pre_len, prelude, sizeof prelude, "<html><head>\n"
                      "<title>Index of %s</title>\n"
                      "</head>\n"
                      "<body>\n"
                      "<h1>Index of %s</h1>\n"
                      "<small><pre>\n", p, p))
                log(0, "Truncated prelude.");

        if (NULL == (entry_list = list_new())) {
                log(0, "list allocation failure: %m");
                goto end;
        }

        list_set_cmp_func(entry_list, (tlist_cmp_func) strcmp);

        while (NULL != (ent = readdir(dir))) {
                char *name = NULL;

                if (NULL == (name = strdup(ent->d_name))) {
                        log(0, "strdup failed: %m");
                        goto end;
                }

                list_add_sorted(entry_list, name);
        }

        struct dir_conv conv;

        conv.n_dir_entries = list_get_size(entry_list);
        conv.cursor = 0;
        conv.buf = &buf;
        conv.buf_len = &buf_len;
        conv.error = 0;
        memcpy(conv.p, p, sizeof p);

        list_map(entry_list, build_directory_buf_cb, &conv);
        if (-1 == conv.error) {
                r = -1;
                goto end;
        }

        /* prepend the prelude and append the postlude */
        if (NULL == (tmp = realloc(buf, buf_len + pre_len + post_len))) {
                log(0, "realloc: %m");
        } else {
                buf = tmp;
                memmove(buf + pre_len, buf, buf_len);
                memcpy(buf, prelude, pre_len);
                memcpy(buf + pre_len + buf_len, postlude, post_len);
                buf_len += pre_len + post_len;
        }

        flag |= BEWS_CONTENT_FLAG_ALLOCATED;

        r = 0;
  end:
        if (dir)
                closedir(dir);

        if (bufp)
                *bufp = buf;
        else
                free(buf);

        if (buf_lenp)
                *buf_lenp = buf_len;

        if (flagp)
                *flagp = flag;

        if (entry_list)
                list_free(entry_list);

        log(2, "path=%s, ret=%d", req->uri.path, r);
        return r;
}

static int bews_set_content_reg(struct request *req, char **bufp,
                                size_t *buf_lenp, enum content_flag *flagp)
{
        char *buf = NULL;
        enum content_flag flag = 0u;
        int datafd = -1;
        int r = -1;
        void *addr = NULL;
        size_t buf_len = req->uri.st.st_size;

        log(2, "path=%s", req->uri.path);

        if ((datafd = open(req->uri.on_disk, O_RDONLY)) < 0) {
                log(0, "open(%s): %m", req->uri.on_disk);
                goto end;
        }

        if (buf_len) {
                addr = mmap(NULL, buf_len, PROT_READ, MAP_PRIVATE, datafd, 0);
                if (MAP_FAILED == addr) {
                        log(0, "mmap: %m");
                        goto end;
                }

                flag |= BEWS_CONTENT_FLAG_MMAPED;
                buf = (char *) addr;
        }


        r = 0;
  end:
        if (buf_lenp)
                *buf_lenp = buf_len;

        if (bufp)
                *bufp = buf;

        if (flagp)
                *flagp = flag;

        if (-1 != datafd)
                (void) close(datafd);

        log(2, "path=%s, ret=%d", req->uri.path, r);
        return r;
}

static int bews_set_content_infos_ext(struct request *req, char **bufp,
                                      size_t *buf_lenp,
                                      enum content_flag *flagp)
{
        int r = -1;
        size_t buf_len = 0;
        char *buf = NULL;
        enum content_flag flag = 0u;

        if (S_ISDIR(req->uri.st.st_mode)) {
                if (bews_set_content_dir(req, &buf, &buf_len, &flag) < 0) {
                        log(0, "directory error");
                        goto end;
                }
        } else if (S_ISREG(req->uri.st.st_mode)) {
                if (bews_set_content_reg(req, &buf, &buf_len, &flag) < 0) {
                        log(0, "regular file error");
                        goto end;
                }
        } else {
                log(0, "unsupported file type");
                goto end;
        }

        r = 0;
  end:
        if (buf_lenp)
                *buf_lenp = buf_len;

        if (bufp)
                *bufp = buf;

        if (flagp)
                *flagp = flag;

        log(2, "ret=%d", r);
        return r;
}

static int bews_set_content_infos(struct request *req, enum code code, char **bufp,
                                  size_t *buf_lenp, enum content_flag *flagp)
{
        int r = -1;
        size_t buf_len = 0, len = 0;
        char *buf = NULL;
        enum content_flag flag = 0u;
        struct bews_ctx *ctx = req->shared;

        log(2, "code=%u", ctx->codes[code].code);

        if (code < CODE_300) {
                if (bews_set_content_infos_ext(req, &buf, &buf_len, &flag) < 0)
                        goto end;
        } else if (code >= CODE_400) {
                char err[512];
                if (esnprintf(len, err, sizeof err,
                              "<html>"
                              "<head><title>%d %s</title></head>"
                              "<body bgcolor=\"white\">"
                              "<center><h1>%d %s</h1></center>"
                              "<hr><center>%s %s (%s) compiled on %s</center>"
                              "</body>"
                              "</html>",
                              ctx->codes[code].code, ctx->codes[code].msg,
                              ctx->codes[code].code, ctx->codes[code].msg,
                              _PROGNAME_, _GITVERSION_, _GITCOMMIT_,
                              _COMPILATIONDATE_))
                        log(0, "Truncated content infos.");

                if (NULL == (buf = strdup(err))) {
                        log(0, "strdup(%s): %m", err);
                        goto end;
                }

                flag |= BEWS_CONTENT_FLAG_ALLOCATED;
                buf_len = strlen(buf);
        }

        r = 0;
  end:
        if (buf_lenp)
                *buf_lenp = buf_len;

        if (bufp)
                *bufp = buf;

        if (flagp)
                *flagp = flag;

        return r;
}

static int bews_response_get(struct request *req)
{
        struct bews_ctx *ctx = req->shared;
        int r = -1;
        enum code code;
        char *buf = NULL;
        size_t buf_len = 0;
        enum content_flag flag = 0u;

        if (req->hint) {
                log(2, "hint.code=%d", req->hint->code);
                code = req->hint->idx;
                goto answer;
        }

        if (bews_set_path_from_uri(req) < 0) {
                log(0, "can't set local path from URI");
                goto end;
        }

        log(1, "URI: %s", req->uri.value);

        if (bews_set_code_from_path(req, &code) < 0) {
                log(0, "can't set status code from path '%s'",
                         req->uri.path);
                goto end;
        }

        log(0, ADDRFMT" %d %s %s [User-Agent: %s, Referer: %s]",
            ADDRTOFMT(req->c_addr),
            ctx->codes[code].code,
            methods[req->method].str,
            req->uri.value,
            req->user_agent ? req->user_agent : "Unknown",
            req->referer ? req->referer : "None");

  answer:
        if (bews_set_content_infos(req, code, &buf, &buf_len, &flag) < 0) {
                log(0, "can't set data length...");
                goto end;
        }

        bews_send_header(req, code, buf_len);
        bews_send_content(req, buf, buf_len, flag);

        r = 0;
  end:
        log(2, "ret=%d", r);
        return r;
}

static int bews_response_put(struct request *req)
{
        (void) req;
        return 0;
}

static int bews_response_post(struct request *req)
{
        (void) req;
        return 0;
}

static int bews_response_head(struct request *req)
{
        struct bews_ctx *ctx = req->shared;
        int r = -1;
        enum code code;
        size_t buf_len;

        if (req->hint) {
                code = req->hint->code;
                goto answer;
        }

        if (bews_set_path_from_uri(req) < 0) {
                log(0, "can't set local path from URI");
                goto end;
        }

        log(1, "URI: %s", req->uri.value);

        if (bews_set_code_from_path(req, &code) < 0) {
                log(0, "can't set status code from path");
                goto end;
        }

        log(0, "%s %s -> %d",
                 methods[req->method].str,
                 req->uri.value,
                 ctx->codes[code].code);

  answer:
        if (bews_set_content_infos(req, code, NULL, &buf_len, NULL) < 0) {
                log(0, "can't set data length...");
                goto end;
        }

        bews_send_header(req, code, buf_len);

        r = 0;
  end:
        log(2, "ret=%d", r);
        return r;
}

static int bews_response_connect(struct request *req)
{
        (void) req;
        return 0;
}

static int bews_response_delete(struct request *req)
{
        (void) req;
        return 0;
}

static int bews_response_options(struct request *req)
{
        (void) req;
        return 0;
}

static int bews_response_trace(struct request *req)
{
        (void) req;
        return 0;
}

void methods_init(void)
{
        for (size_t i = 0; i < N_ELEMS(methods); i++)
                methods[i].len = strlen(methods[i].str);
}

void request_field_init(void)
{
        for (size_t i = 0; i < N_ELEMS(field_name); i++)
                field_name[i].len = strlen(field_name[i].name);
}

static char *bews_uri_type_to_str(enum uri_type type)
{
        switch (type) {
#define MAP(x) case x: return #x
                MAP(URI_TYPE_STAR);
                MAP(URI_TYPE_ABSOLUTE_URI);
                MAP(URI_TYPE_ABSOLUTE_PATH);
                MAP(URI_TYPE_AUTHORITY);
#undef MAP
        }

        return "invalid uri type";
}

static unsigned fd_hash_func(const void *data)
{
        const unsigned char *fd = data;
        return generic_buffer_hashcode(fd, sizeof (int));
}

static int fd_equal_func(const void *a, const void *b)
{
        const int *fda = a;
        const int *fdb = b;

        return *fda == *fdb;
}

struct bews_ctx *bews_ctx_new(void)
{
        struct bews_ctx *ctx = NULL;

        if (NULL == (ctx = calloc(1, sizeof *ctx))) {
                log(0, "malloc: %m");
                goto end;
        }

        if (NULL == (ctx->h = hash_new(101, fd_hash_func, fd_equal_func))) {
                log(0, "Failed to create hashtable");
                goto end;
        }

        pthread_mutex_init(&ctx->lock, NULL);
        ctx->lock_inited = 1;

        ctx->port = BEWS_DEFAULT_PORT;

        if (NULL == (ctx->user_name = strdup(BEWS_DEFAULT_USER_NAME))) {
                log(0, "strdup(%s): %m", BEWS_DEFAULT_USER_NAME);
                free(ctx);
                ctx = NULL;
                goto end;
        }

        if (NULL == (ctx->root_dir = strdup(BEWS_DEFAULT_ROOT_DIR))) {
                log(0, "strdup(%s): %m", BEWS_DEFAULT_ROOT_DIR);
                free(ctx->user_name);
                free(ctx);
                ctx = NULL;
                goto end;
        }

        ctx->codes = &codes[0];

        ctx->driver.get = bews_response_get;
        ctx->driver.put = bews_response_put;
        ctx->driver.post = bews_response_post;
        ctx->driver.head = bews_response_head;
        ctx->driver.delete = bews_response_delete;
        ctx->driver.connect = bews_response_connect;
        ctx->driver.options = bews_response_options;
        ctx->driver.trace = bews_response_trace;

  end:
        return ctx;
}

void bews_ctx_free(struct bews_ctx *ctx)
{
        if (ctx->lock_inited)
                pthread_mutex_destroy(&ctx->lock);

        hash_free(ctx->h);
        free(ctx->user_name);
        free(ctx->root_dir);
        free(ctx);
}

/* expected format:  "<field name>: <value><eol>+"  */
int do_parse_request_field(struct request *req, char *buf, size_t buf_len)
{
        int r = -1;
        int found = 0;
        size_t min = 0;
        const char eol = '\n';
        char *p = NULL;
        char *tmp_buf = NULL;
        size_t tmp_len = 0;

        if (NULL == strnchr(buf, ':', buf_len)) {
                log(0, "missing separator in : '%s'", buf);
                r = 0;
                goto end;
        }

        if (NULL == (p = strnchr(buf, eol, buf_len))) {
                log(0, "missing end of line in: '%s'", buf);
                r = 0;
                goto end;
        }

        tmp_buf = buf;

        while (p >= buf && ('\r' == *p || '\n' == *p))
                p--;

        tmp_len = p - buf + 1;

        for (size_t i = 0; i < N_ELEMS(field_name) && 0 == found; i++) {
                char *val = NULL;
                size_t len = field_name[i].len;
                min = MIN(tmp_len, len);

                if (0 != strncasecmp(field_name[i].name, tmp_buf, min))
                        continue;

                if (':' != buf[min])
                        continue;

                val = buf + min + 1;

                while (val && isspace(*val))
                        val++;

                if (! val)
                        continue;

                if (NULL == (req->field[i] = strndup(val, tmp_len-(buf-val)))) {
                        log(0, "strndup: %m");
                        goto end;
                }

#define CHECK_FIELD(F, f) do {                                          \
                        if (! strncasecmp(buf,                          \
                                          field_name[F].name,           \
                                          field_name[F].len)) {         \
                                if (NULL == (req-> f = strdup(val))) {  \
                                        log(0, "strdup: %m");           \
                                        goto end;                       \
                                }                                       \
                                                                        \
                                /* remove the trailing garbage */       \
                                req-> f[strcspn(req-> f, "\r\n")] = 0;  \
                        }                                               \
                } while (0)

                CHECK_FIELD(HOST, host);
                CHECK_FIELD(REFERER, referer);
                CHECK_FIELD(USER_AGENT, user_agent);

#undef CHECK_FIELD

                found = 1;
        }

        r = (1 == found) ? 0 : -1;
  end:
        log(2, "ret=%d", r);
        return r;
}

/**
 * Request-Line   = Method SP Request-URI SP HTTP-Version CRLF
 */
int do_parse_request_line(struct request *req, char *buf, size_t buf_len,
                          size_t *request_lenp)
{
        size_t len = 0;
        int r = -1;
        char *p;
        int found = -1;
        char *tmp_buf;
        size_t tmp_len;
        size_t token_len;

        if (NULL == (p = strnchr(buf, '\n', buf_len))) {
                log(0, "missing end of line");
                goto end;
        }

        tmp_buf = buf;

        while (p >= buf && ('\r' == *p || '\n' == *p))
                p--;

        len = tmp_len = p - buf + 1;

        /* we ignore extention methods */
        for (size_t i = 0; i < N_ELEMS(methods); i++) {
                if (0 == strncmp(methods[i].str, buf, methods[i].len)) {
                        found = i;
                        break;
                }
        }

        if (found < 0) {
                log(0, "can't find any method in '%s'", tmp_buf);
                goto end;
        }

        req->method = methods[found].id;

        tmp_buf += methods[found].len;
        tmp_len -= methods[found].len;

        if (! isspace(*tmp_buf)) {
                log(0, "missing space after method name");
                goto end;
        }

        /* consume the spaces */
        while (tmp_len && isspace(*tmp_buf)) {
                tmp_buf++;
                tmp_len--;
        }

        /* TODO: accept "GET  HTTP/1.1", where the double space is implicitly
         * the root_dir / or whatever */

        /* get request-uri */
        /* Request-URI    = "*" | absoluteURI | abs_path | authority */
        if (NULL == (p = strnchr(tmp_buf, ' ', len))) {
                log(1, "missing HTTP version: '%s'", tmp_buf);
                goto end;
        }

        token_len = p - tmp_buf;

        if (NULL == (req->uri.value = strndup(tmp_buf, token_len))) {
                log(0, "strndup: %m");
                goto end;
        }
        req->uri.value_len = token_len;

        if (0 == strncasecmp("http://", tmp_buf, strlen("http://"))) {
                req->uri.type = URI_TYPE_ABSOLUTE_URI;
        } else {
                switch (tmp_buf[0]) {
                case '*':
                        req->uri.type = URI_TYPE_STAR;
                        break;
                case '/':
                        req->uri.type = URI_TYPE_ABSOLUTE_PATH;
                        break;
                default:
                        req->uri.type = URI_TYPE_AUTHORITY;
                }
        }

        tmp_buf += token_len;

        /* consume the spaces */
        while (tmp_len && isspace(*tmp_buf))
                tmp_buf++;

        /* get http version */
        char *prefix = "HTTP/1.";
        size_t prefix_len = strlen(prefix);

        // is version unset?
        if (0 == req->version) {
                if (0 == strncmp(prefix, tmp_buf, prefix_len)) {
                        tmp_buf += prefix_len;

                        switch (tmp_buf[0]) {
                        case '0':
                                req->version = HTTP_10;
                                break;
                        case '1':
                                req->version = HTTP_11;
                                break;
                        default:
                                log(1, "unrecognized http version, "
                                    "set it as HTTP/1.1 : %s", tmp_buf);
                                req->version = HTTP_11;
                                break;
                        }
                }
        }

        r = 0;

        log(2, "method=%s uri_type=%s uri=%s version=%s",
            methods[req->method].str,
            bews_uri_type_to_str(req->uri.type),
            req->uri.value,
            req->version == HTTP_10 ? "HTTP/1.0" : "HTTP/1.1");
  end:
        if (request_lenp)
                *request_lenp = len;

        log(2, "ret=%d", r);
        return r;
}

static int do_parse_request(struct request *req, char *buf, size_t buf_len)
{
        int r = -1;
        char *p = NULL;
        size_t request_len;
        char *tmp_buf;
        size_t tmp_len;
        char *line = NULL;

        if (do_parse_request_line(req, buf, buf_len, &request_len) < 0) {
                log(0, "incorrect request line");
                goto end;
        }

        tmp_buf = buf + request_len;
        tmp_len = buf_len - request_len;

        while (tmp_buf && ('\r' == *tmp_buf || '\n' == *tmp_buf)) {
                tmp_buf++;
                tmp_len--;
        }

        while (tmp_buf < buf + buf_len) {

                if (NULL == (p = strchr(tmp_buf, '\n'))) {
                        log(0, "invalid request: '%s'", tmp_buf);
                        goto end;
                }

                tmp_len = p - tmp_buf + 1;
                if (NULL == (line = strndupa(tmp_buf, tmp_len))) {
                        log(0, "strndup: %m");
                        goto end;
                }

                if (do_parse_request_field(req, line, tmp_len) < 0) {
                        log(2, "unrecognized field: %s", line);
                        tmp_buf += tmp_len;
                        continue;
                }

                while (p && ('\r' == *p || '\n' == *p))
                        p++;

                tmp_buf = p;
        }

        r = 0;
  end:
        log(2, "ret=%d", r);
        return r;
}

static int do_answer(struct request *req)
{
        int r = 0;
        struct bews_ctx *ctx = req->shared;
        int (*cb)(struct request *) = NULL;

        pthread_mutex_lock(&ctx->lock);

        int (*response_map_cb[N_METHODS])(struct request *) = {
          [GET] =  ctx->driver.get,
          [HEAD] = ctx->driver.head,
        };

        cb = response_map_cb[req->method];

        pthread_mutex_unlock(&ctx->lock);

        if (cb)
                r = cb(req);

        return r;
}

int do_handle_request(struct request *req)
{
        char *found = NULL;
        int r = -1;
        size_t header_len = 0;
        char *header = NULL;

        if (req->hint) {
                log(2, "code=%d msg=%s", req->hint->code, req->hint->msg);
                goto answer;
        }

        char *eohs[] = {
                /* end of requests, the order matters */
                "\n\r\n",
                "\n\n",
        };

        for (size_t i = 0; i < N_ELEMS(eohs) && !found; i++) {
                found = strnstr(req->reqbuf, eohs[i], req->reqbuf_len);
                if (! found)
                        continue;

                header_len = found - req->reqbuf + 1;
                if (NULL == (header = strndupa(req->reqbuf, header_len))) {
                        log(0, "strndup: %m");
                        goto end;
                }

                if (do_parse_request(req, header, strlen(header)) < 0) {
                        log(0, "malformed request");
                        req->hint = &req->shared->codes[CODE_400];
                        goto answer;
                }
        }

        if (! found) {
                log(0, "can't find any request delimiter");
                goto end;
        }

        log(1, "header sucessfully parsed");

 answer:
        if (do_answer(req) < 0) {
                log(0, "error in answer");
                goto end;
        }

        r = 0;
  end:
        log(2, "ret=%d", r);
        return r;
}
