#include <grp.h>
#include <pwd.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <signal.h>

#include "bews.h"
#include "log.h"
#include "utils.h"
#include "tpool.h"

#define MAXEVENTS 128

ttask_pool *reqpool;

static void signal_handler_usr1(int signo)
{
        (void) signo;

        log(0, "SIGUSR1: increase log level (current: %d)", verbose_level);
        if (verbose_level < MAX_VERBOSE_LEVEL)
                verbose_level++;
}

static void signal_handler_usr2(int signo)
{
        (void) signo;

        log(0, "SIGUSR2: decrease log level (current: %d)", verbose_level);
        if (verbose_level > MIN_VERBOSE_LEVEL)
                verbose_level--;
}

static void usage(void)
{
        fprintf(stderr, "Usage: %s [OPTIONS]\n"
                "OPTIONS\n"
                "\t-h, --help\t\tdisplay this message\n"
                "\t-p, --port=PORT\t\tthe port the server will listen to\n"
                "\t-r, --rootdir=ROOT\tthe directory where lies the root document\n"
                "\t-v\t\t\tincrease the verbose level\n"
                "\t-d, --daemonize\t\trun as daemon\n"
                "\t-V, --version\t\tshow the version\n",
                _PROGNAME_);
}

static void version(void)
{
        fprintf(stderr, "%s %s (%s) compiled on %s\n",
                _PROGNAME_, _GITVERSION_, _GITCOMMIT_, _COMPILATIONDATE_);
}

static void do_process_request_func(struct request *req)
{
        ssize_t count;
        int done = 0;
        char autobuf[4096];
        int eoh = 0;

        if (-1 == (count = read(req->fd, autobuf, sizeof autobuf))) {
                if (EAGAIN != errno) {
                        log(0, "read: %m");
                        done = 1;
                }
                goto end;
        }

        if (sizeof autobuf <= req->reqbuf_len + count) {
                log(0, "request too big (size %zu bytes)", count);
                req->hint = &req->shared->codes[CODE_400];
                goto answer;
        }

        log(1, "read %zd bytes on fd %d", count, req->fd);
        if (! count) {
                /* remote has closed the connection */
                log(1, "remote closed the connection (fd %d)",
                         req->fd);
                done = 1;
                goto end;
        }

        if (req->reqbuf) {
                char *tmp = realloc(req->reqbuf, req->reqbuf_len + count + 1);
                if (! tmp) {
                        log(0, "realloc: %m");
                        free(req->reqbuf);
                        req->reqbuf = NULL;
                        req->reqbuf_len = 0;
                        goto end;
                }

                req->reqbuf = tmp;
        } else {
                req->reqbuf = malloc(count + 1);
                if (! req->reqbuf) {
                        log(0, "malloc: %m");
                        req->reqbuf_len = 0;
                        goto end;
                }

        }

        memcpy(req->reqbuf + req->reqbuf_len, autobuf, count);
        req->reqbuf_len += count;
        req->reqbuf[req->reqbuf_len] = 0;

        char *eohs[] = {
                /* end of requests, the order matters */
                "\n\r\n",
                "\n\n",
        };

        for (size_t i = 0; i < N_ELEMS(eohs); i++) {
                if (strnstr(req->reqbuf, eohs[i], req->reqbuf_len)) {
                        eoh = 1;
                        break;
                }
        }

        if (! eoh)
                return;

  answer:
        if (do_handle_request(req) < 0) {
                log(0, "bad request: %m");
                goto end;
        }

  end:
        if (done) {
                log(1, "Closed connection on descriptor %d",
                         req->fd);

                /* Closing the descriptor will make epoll remove it
                   from the set of descriptors which are monitored. */
                (void) close(req->fd);
        }
}

static int do_bind(uint16_t p)
{
        struct addrinfo hints;
        struct addrinfo *result, *rp;
        int rc;
        int sfd;
        char strp[16] = "";
        int len = 0;

        memset(&hints, 0, sizeof hints);

        hints.ai_family = AF_UNSPEC;     /* IPv4 and IPv6 */
        hints.ai_socktype = SOCK_STREAM; /* TCP */
        hints.ai_flags = AI_PASSIVE;     /* all interfaces */

        if (esnprintf(len, strp, sizeof strp, "%u", p))
                log(0, "Truncated buffer.");

        if ((rc = getaddrinfo(NULL, strp, &hints, &result))) {
                log(0, "getaddrinfo: %s", gai_strerror(rc));
                sfd = -1;
                goto end;
        }

        for (rp = result; rp; rp = rp->ai_next) {
                sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
                if (-1 == sfd)
                        continue;

                if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR,
                               (int []) {1}, sizeof(int)) < 0) {
                        log(0, "setsockopt: %m");
                        sfd = -1;
                        goto end;
                }

                if (0 == bind(sfd, rp->ai_addr, rp->ai_addrlen))
                        break;

                (void) close(sfd);
        }

        if (! rp) {
                log(0, "can't bind anyone: %m");
                sfd = -1;
                goto end;
        }

        freeaddrinfo(result);

  end:
        return sfd;
}

static int do_set_non_blocking(int fd)
{
        int flags;
        int ret = -1;

        if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
                log(0, "fcntl: %m");
                goto end;
        }

        flags |= O_NONBLOCK;

        if (fcntl(fd, F_SETFL, flags) < 0) {
                log(0, "fcntl: %m");
                goto end;
        }

        ret = 0;
  end:
        return ret;
}

static int do_process_waiting_data(struct bews_ctx *ctx, struct epoll_event event)
{
        int ret = -1;
        struct request *req;
        struct sockaddr *addr;

        if (NULL == (addr = hash_item_get(ctx->h, &event.data.fd))) {
                log(0, "Can't find an address matching fd %d", event.data.fd);
                goto end;
        }

        if (NULL == (req = calloc(1, sizeof *req))) {
                log(0, "calloc failed: %m");
                goto end;
        }

        struct in_addr *in = &((struct sockaddr_in *) addr)->sin_addr;

        req->shared = ctx;
        memcpy(&req->c_addr, in, sizeof req->c_addr);
        req->fd = event.data.fd;
        req->task.func = (ttask_func) do_process_request_func;
        ttask_pool_put(reqpool, (ttask *) req);

        ret = 0;
  end:
        return ret;
}

static int do_handle_notification(thash *h, int fd, int efd,
                                  struct epoll_event event)
{
        log(1, "fd=%d, efd=%d", fd, efd);

        while (1) {
                int infd;
                char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
                struct sockaddr in_addr;
                void *value = NULL;
                socklen_t in_len;

                in_len = sizeof in_addr;
                if ((infd = accept(fd, &in_addr, &in_len)) < 0) {
                        if ((errno == EAGAIN) ||
                            (errno == EWOULDBLOCK)) {
                                /* we've processed all incoming connections */
                                break;
                        } else {
                                log(0, "accept: %m");
                                break;
                        }
                }

                if (0 == getnameinfo(&in_addr, in_len, hbuf, sizeof hbuf,
                                     sbuf, sizeof sbuf,
                                     NI_NUMERICHOST | NI_NUMERICSERV)) {
                        log(1, "Connection on %s:%s, fd=%d", hbuf, sbuf, infd);
                }

                log(2, "Connection on %s:%s, fd=%d", hbuf, sbuf, infd);

                if (do_set_non_blocking(infd) < 0) {
                        log(0, "can't set fd=%d in non-blocking", infd);
                        goto err;
                }

                memset(&event, 0, sizeof event);

                event.data.fd = infd;
                event.events = EPOLLIN | EPOLLET;
                if (epoll_ctl(efd, EPOLL_CTL_ADD, infd, &event) < 0) {
                        log(0, "epoll_ctl: %m");
                        goto err;
                }

                if ((value = hash_item_get(h, &infd))) {
                        memcpy(value, &in_addr, sizeof in_addr);
                } else {
                        /* we ignore the result because of the previous if () */
                        int *key = NULL;
                        struct sockaddr *addr = NULL;

                        if (NULL == (key = malloc(sizeof *key))) {
                                log(0, "malloc: %m");
                                goto err;
                        }

                        *key = infd;

                        if (NULL == (addr = malloc(sizeof *addr))) {
                                log(0, "malloc: %m");
                                free(key);
                                goto err;
                        }

                        memcpy(addr, &in_addr, sizeof *addr);
                        (void) hash_item_put(h, key, addr);
                }
        }

        return 0;
  err:
        return -1;
}

static int do_handle_event(struct bews_ctx *ctx, int fd, int efd,
                           struct epoll_event e)
{
        int ret = -1;

        log(1, "fd=%d, epoll_fd=%d, e.data.fd=%d", fd, efd, e.data.fd);

        if ((e.events & EPOLLERR) || (e.events & EPOLLHUP) ||
            (! (e.events & EPOLLIN))) {
                log(0, "epoll_wait: %m");
                close(e.data.fd);
                goto ok;
        }

        if (fd == e.data.fd) {
                if (do_handle_notification(ctx->h, fd, efd, e) < 0)
                        goto err;
        } else {
                if (do_process_waiting_data(ctx, e) < 0)
                        goto err;
        }

  ok:
        ret = 0;
  err:
        return ret;
}

static int do_loop(struct bews_ctx *ctx, int fd, int efd,
                   struct epoll_event *events)
{
        int ret = -1;

        while (1) {
                int n;

                n = epoll_wait(efd, events, MAXEVENTS, -1);
                for (int i = 0; i < n; i++) {
                        if (do_handle_event(ctx, fd, efd, events[i]) < 0)
                                goto err;
                }
        }

        ret = 0;
  err:
        return ret;
}

static void reqpool_delete_func(ttask_pool *pool, ttask *task)
{
        (void) pool;

        struct request *req = (struct request *) task;

        if (! req)
                return;

        for (int i = 0; i < HEADER_FIELD_NB; i++)
                free(req->field[i]);

        free(req->uri.value);
        free(req->uri.path);
        free(req->reqbuf);
        free(req->host);
        free(req->referer);
        free(req->user_agent);
        free(req);
}

static int run(struct bews_ctx *ctx)
{
        int fd = -1;
        int efd;
        struct epoll_event event;
        struct epoll_event *events = NULL;
        int ret = -1;
        struct passwd *pw = NULL;
        gid_t g;
        uid_t u;

        if ((fd = do_bind(ctx->port)) < 0) {
                log(0, "create and bind failed");
                goto end;
        }

        if (do_set_non_blocking(fd) < 0) {
                log(0, "can't set non blocking socket");
                goto end;
        }

        if (listen(fd, SOMAXCONN) < 0) {
                log(0, "listen: %m");
                goto end;
        }

        if (-1 == (efd = epoll_create1(0))) {
                log(0, "epoll_create: %m");
                goto end;
        }

        event.data.fd = fd;
        event.events = EPOLLIN | EPOLLET;

        if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event) < 0) {
                log(0, "epoll_ctl: %m");
                goto end;
        }

        if (NULL == (events = malloc(MAXEVENTS * sizeof *events))) {
                log(0, "malloc: %m");
                goto end;
        }

        memset(events, 0, MAXEVENTS * sizeof *events);

        if (0 == is_daemonized) {
                log(0, "WARNING!  No privilege drop because of missing -d");
        } else {
                switch (fork()) {
                case 0:
                        /* In the child */
                        break;
                case -1:
                        log(0, "fork: %m");
                        goto end;
                default:
                        /* In the parent: die and let live! */
                        exit(EXIT_SUCCESS);
                }
        }

        if (NULL == (pw = getpwnam(ctx->user_name))) {
                log(0, "getpwnam: %m");
                goto end;
        }

        if (chroot(ctx->root_dir) < 0) {
                log(0, "chroot: %m");
                goto end;
        }

        if (chdir("/") < 0) {
                log(0, "chdir(%s) failed: %m", ctx->root_dir);
                goto end;
        }

        u = pw->pw_uid;
        g = pw->pw_gid;

        if (setgroups(1, &g) || setresgid(g, g, g) || setresuid(u, u, u)) {
                log(0, "set privs: %m");
                goto end;
        }

        log(0, "Starting HTTP server...");
        log(0, "Listening on port %u", ctx->port);
        log(0, "Serving files in %s", ctx->root_dir);

        if (NULL == (reqpool = ttask_pool_create(DEFAULT_N_WORKERS))) {
                log(0, "can't create request pool");
                goto end;
        }

        task_pool_set_delete_func(reqpool, reqpool_delete_func);

        if (do_loop(ctx, fd, efd, events) < 0) {
                log(0, "error in event loop handler");
                goto end;
        }


        ret = 0;
  end:
        if (-1 != fd)
                (void) close(fd);

        free(events);
        ttask_pool_free(reqpool);

        return ret;
}

int main(int argc, char **argv)
{
        int ret = EXIT_FAILURE;
        char opt = 0;
        int opt_index = 0;
        struct bews_ctx *ctx = NULL;

        static struct option long_opt[] = {
                {"help",           no_argument,       0, 'h'},
                {"port",           required_argument, 0, 'p'},
                {"rootdir",        required_argument, 0, 'r'},
                {"user",           required_argument, 0, 'u'},
                {"daemonize",      no_argument,       0, 'd'},
                {"version",        no_argument,       0, 'V'},
                {0, 0, 0, 0},
        };

        verbose_level = 1;

        openlog(basename(argv[0]), LOG_CONS | LOG_NOWAIT | LOG_PID, LOG_USER);

        if (NULL == (ctx = bews_ctx_new())) {
                log(0, "context creation failed");
                goto end;
        }

        while (-1 != (opt = getopt_long(argc, argv, "hp:r:u:vVd",
                                        long_opt, &opt_index)))  {
                switch (opt) {
                case 'V':
                        version();
                        ret = EXIT_SUCCESS;
                        goto end;
                case 'd':
                        is_daemonized = 1;
                        break;
                case 'v':
                        verbose_level++;
                        break;
                case 'h':
                        usage();
                        ret = EXIT_SUCCESS;
                        goto end;
                case 'p':
                        ctx->port = strtoul(optarg, NULL, 10);
                        break;
                case 'u':
                        if (NULL == (ctx->user_name = strdup(optarg))) {
                                log(0, "strdup: %m");
                                goto end;
                        }
                        break;
                case 'r':
                        if (NULL == (ctx->root_dir = realpath(optarg, NULL))) {
                                log(0, "realpath(%s): %m", optarg);
                                goto end;
                        }

                        while ('/' == ctx->root_dir[strlen(ctx->root_dir) - 1])
                                ctx->root_dir[strlen(ctx->root_dir) - 1] = 0;

                        break;
                default:
                        usage();
                        goto end;
                }
        }

        request_field_init();
        methods_init();

        signal(SIGPIPE, SIG_IGN);
        signal(SIGCHLD, SIG_IGN);
        signal(SIGUSR1, signal_handler_usr1);
        signal(SIGUSR2, signal_handler_usr2);

        /* daemonization starts here */
        if (1 == is_daemonized) {
                if ((ret = daemon(1, 1)) < 0) {
                        log(0, "daemon: %m");
                        exit(EXIT_FAILURE);
                }
        }

        ret = run(ctx);
  end:
        if (ctx)
                bews_ctx_free(ctx);
        closelog();

        return ret;
}

