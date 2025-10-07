#ifndef UTILS_H
#define UTILS_H



#define _STRIZE(x) #x
#define STRIZE(x) _STRIZE(x)

#define N_ELEMS(x) (sizeof x / sizeof x[0])

#define esnprintf(out, buf, len, ...)                                   \
        ((int) (out = snprintf(buf, len, __VA_ARGS__))) >= (int) len || (int) out < 0


#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define MAX(x, y) ((x) > (y) ? (x) : (y))

char *strnstr(char *haystack, char *needle, size_t len);
char *strnchr(char *haystack, char needle, size_t len);



#endif /* UTILS_H */
