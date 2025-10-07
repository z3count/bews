#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "bews.h"
#include "utils.h"

#define PATH_MAX 4096
#define N_ELEMS(x) (sizeof x / sizeof x[0])

extern struct code_hdl codes[CODE_NB];

struct utest {
        char *source;
        struct request req;
        struct request exp_req;
        int exp_status;
};

struct utest expected_fields[] = {
        {
                // correct Host: line
                .source = "Host: foo.org\r\n",
                .req = { .field[HOST] = NULL },
                .exp_req = { .field[HOST] = "foo.org\r\n" },
                .exp_status = 0,
        },

        {
                // no space after ":"
                .source = "Host:foo.org\r\n",
                .req = { .field[HOST] = NULL },
                .exp_req = { .field[HOST] = "foo.org\r\n" },
                .exp_status = 0,
        },

        {
                // several spaces after ":"
                .source = "Host:    foo.org\r\n",
                .req = { .field[HOST] = NULL },
                .exp_req = { .field[HOST] = "foo.org\r\n" },
                .exp_status = 0,
        },

        {
                // field name is case-insensitive, "HOST" is not specified
                // in the RFC 2616 but we accept it
                .source = "HOST: foo.org\r\n",
                .req = { .field[HOST] = NULL },
                .exp_req = { .field[HOST] = "foo.org\r\n" },
                .exp_status = 0,
        },

};

static void test_parse_request_field(void)
{
        int status;
        size_t i;

        for (i = 0; i < N_ELEMS(expected_fields); i++) {
                struct utest f = expected_fields[i];

                status = do_parse_request_field(&f.req, f.source, strlen(f.source));

                assert(f.exp_status == status);

                if (-1 == status) {
                        /* we expected a failure */
                        continue;
                }

                assert(NULL != f.req.field[HOST]);

                assert(0 == strcmp(f.exp_req.field[HOST],
                                   f.req.field[HOST]));
        }

        printf("[+] %s\n", __func__);
}

struct utest expected_reqline[] = {
        {
                .source = "GET / HTTP/1.1\r\n",
                .req = { .uri = { .value = NULL } },
                .exp_req = {
                        .uri = { .value = "/", .type = URI_TYPE_ABSOLUTE_PATH },
                        .method = GET,
                        .version = HTTP_11,
                },
                .exp_status = 0,
        },

        {
                .source = "GET foo/bar HTTP/1.0\r\n",
                .req = {
                        .uri = { .value = NULL, .type = -1 },
                },
                .exp_req = {
                        .uri = { .value = "foo/bar", .type = URI_TYPE_AUTHORITY },
                        .method = GET,
                        .version = HTTP_10
                },
                .exp_status = 0,
        },

        {
                .source = "PROUT\r\n",
                .exp_status = -1,
        }
};


static void test_parse_request_line(void)
{
        int status;
        size_t i;

        for (i = 0; i < N_ELEMS(expected_reqline); i++) {
                struct utest r = expected_reqline[i];

                status = do_parse_request_line(&r.req, r.source, strlen(r.source), NULL);

                assert(r.exp_status == status);

                if (-1 == status) {
                        /* we expected a failure */
                        continue;
                }

                assert(NULL != r.req.uri.value);

                assert(r.req.version == r.exp_req.version);
                assert(r.req.method == r.exp_req.method);

                assert(0 == strcmp(r.exp_req.uri.value,
                                    r.req.uri.value));

        }

        printf("[+] %s\n", __func__);
}

struct uri_utest {
        struct request req;
        char *exp_path;
        int exp_status;
};

struct uri_utest uri_utests[] = {
        {
                .req = {
                        .uri = { .value = "/" },
                },
                .exp_path = "index.html",
                .exp_status = 0,
        },

        {
                .req = {
                        // trailing space
                        .uri = { .value = "/ " },
                },
                .exp_path = "index.html",
                .exp_status = 0,
        },

        {
                .req = {
                        .uri = { .value = "" },
                },
                .exp_path = "index.html",
                .exp_status = 0,
        },

        {
                .req = {
                        .uri = { .value = "/index.html" },
                },
                .exp_path = "index.html",
                .exp_status = 0,
        },

        {
                .req = {
                        .uri = { .value =  NULL },
                },
                .exp_path = "",
                .exp_status = -1,
        },

        {
                .req = {
                        .uri = { .value = "ENOENT" },
                },
                .exp_path = "index.html",
                .exp_status = 0,
        },

        {
                .req = {
                        /* existing file */
                        .uri = { .value =  "/usr/local"},
                },
                /* remove the leading space */
                .exp_path = "usr/local",
                .exp_status = 0,
        },

        {
                .req = {
                        /* with a trailing space :
                         *
                         * we use an array here, because the code will try
                         * to modify the string (set a \0 at the end of
                         * the path), which is an UB for string literal
                         */
                        .uri = {
                                .value =  (char []){"/usr/local  "},
                                .value_len = sizeof "/usr/local" - 1,
                                },
                },
                .exp_path = "usr/local",
                .exp_status = 0,
        },
};

static void test_set_path_from_uri(void)
{
        char buf[4096];
        int status;
        size_t i;

        for (i = 0; i < N_ELEMS(uri_utests); i++) {
                memset(buf, 0, sizeof buf);

                status = bews_set_path_from_uri(&uri_utests[i].req);
                assert(status == uri_utests[i].exp_status);

                if (-1 == status)
                        continue;

                assert(0 == strcmp(uri_utests[i].exp_path,
                                   uri_utests[i].req.uri.path));

                free(uri_utests[i].req.uri.path);
                uri_utests[i].req.uri.path = NULL;
        }

        printf("[+] %s\n", __func__);
}

static void test_set_code_from_path(void)
{
        int status;
        enum code code;
        size_t i;
        struct bews_ctx ctx = { .root_dir = ""};

        struct {
                struct request req;
                enum code exp_code;
                int exp_status;
        } code_utests[] = {
                {
                        .req = { .uri = { .path = "/etc/passwd" },
                                 .shared = &ctx} ,
                        .exp_code = CODE_200,
                        .exp_status = 0,
                },

                {
                        .req = { .uri = { .path = "doesnt_exist" },
                                 .shared = &ctx },
                        .exp_code = CODE_404,
                        .exp_status = 0,
                },

                {
                        .req = { .uri = { .path = "/etc" }, .shared = &ctx },
                        .exp_code = CODE_301,
                        .exp_status = 0,
                },

                {
                        .req = { .uri = { .path = "/this/../is/a/malicious"
                                          "/../path" }, .shared = &ctx },
                        .exp_code = CODE_404,
                        .exp_status = 0,
                },
        };

        for (i = 0; i < N_ELEMS(code_utests); i++) {
                memset(code_utests[i].req.uri.on_disk, 0, sizeof code_utests[i].req.uri.on_disk);
                status = bews_set_code_from_path(&code_utests[i].req, &code);

                assert(status == code_utests[i].exp_status);

                if (-1 == status)
                        continue;

                assert(code == code_utests[i].exp_code);
        }

        printf("[+] %s\n", __func__);
}

static void test_bews_url_decode(void)
{
        size_t i;

        static struct {
                char *encoded;
                char *expected_decoded;
                int expected_result; // 0 is OK, != is KO
        } set[] = {
                { "", "", 0 },
                { "foo", "", -1 },
                { "foo", "foo", 0 },
                { "small%20space", "small space", 0 },
                { "arob%40se", "arob@se", 0 },
        };

        for (i = 0; i < N_ELEMS(set); i++) {
                char decoded_buf[PATH_MAX] = "";
                int ret;

                bews_url_dummy_decode(decoded_buf, set[i].encoded);
                ret = strcmp(decoded_buf, set[i].expected_decoded);
                if (ret != set[i].expected_result) {
                        if (0 == ret || 0 == set[i].expected_result) {
                                printf("expected '%s', got '%s'",
                                       set[i].expected_decoded, decoded_buf);
                        }
                }

                assert(!! ret == !! set[i].expected_result);
        }

        printf("[+] %s\n", __func__);
}

int main(void)
{
        methods_init();
        request_field_init();

        test_parse_request_field();
        test_parse_request_line();
        test_set_path_from_uri();
        test_set_code_from_path();
        test_bews_url_decode();

        return EXIT_SUCCESS;
}
