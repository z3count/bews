#include <string.h>

#include "utils.h"

#define BUF_MAXSZ 2000

char *strnstr(char *haystack, char *needle, size_t len)
{
        char buf[len + 1];
        char *found = NULL;

        if (len > BUF_MAXSZ)
                return NULL;

        memcpy(buf, haystack, len);
        buf[len] = 0;

        if (NULL == (found = strstr(buf, needle)))
                return NULL;

        return haystack + (found - buf);
}

char *strnchr(char *haystack, char needle, size_t len)
{
        size_t min = MIN(strlen(haystack), len);
        char *p = (char *) haystack;
        size_t i = 0;

        while (i <= min) {
                if (needle == *(p + i))
                        return p + i;

                i++;
        }

        return NULL;
}
