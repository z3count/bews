#ifndef LOG_H
#define LOG_H

#include <syslog.h>
#include <stdarg.h>

#include "main.h"

#define MAX_VERBOSE_LEVEL 7
#define MIN_VERBOSE_LEVEL 0

extern int verbose_level;
extern int is_daemonized;

#define log(v, fmt, ...)                                                \
        do {                                                            \
  	    if (v >= verbose_level) break;				\
                                                                        \
                char buf[64], pfx[128];                                 \
                time_t t;                                               \
                struct tm *tmp;                                         \
                                                                        \
                buf[0] = pfx[0] = '\0';                                 \
                t = time(NULL);                                         \
                tmp = localtime(&t);                                    \
                if (! tmp)                                              \
                        break;                                          \
                                                                        \
                if (strftime(buf, sizeof buf, "%F %T ", tmp) == 0)      \
                        break;                                          \
                                                                        \
                if (v > 0)                                              \
                        snprintf(pfx, sizeof pfx, "%s:%s:%d ",          \
                                 __FILE__, __func__, __LINE__);         \
                                                                        \
                if (is_daemonized)                                      \
                        syslog(LOG_ERR, "%s%s" fmt "\n",                \
                               buf, pfx, ##__VA_ARGS__);                \
                else                                                    \
                        printf("%s%s" fmt "\n", buf, pfx,               \
                               ##__VA_ARGS__);                          \
        } while (0)

#endif /* LOG_H */
