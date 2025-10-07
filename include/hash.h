
#ifndef __HASH_H__
#define __HASH_H__

#include <inttypes.h>
#include <stdlib.h>

typedef unsigned (*thash_func)(const void *);
typedef int (*titerate_func)(const void *, const void *, void *);
typedef void (*tfree_func)(void *);
typedef int (*tequal_func)(const void *, const void *);

typedef struct shash thash;

enum {
        HASH_SUCCESS,
        HASH_FAILURE,
        HASH_ENOENT,
        HASH_EEXIST,
        HASH_ENOMEM,
};

unsigned int generic_buffer_hashcode(const unsigned char *buf, size_t len);
unsigned int string_hashcode(const void *data);

size_t hash_sizeof(thash *hash);
size_t hash_get_n_items(thash *hash);
int hash_item_set(thash *hash, void *key, void *value);
int hash_item_put(thash *hash, void *key, void *value);
void *hash_item_get(thash *hash, const void *key);
int hash_item_update(thash *hash, void *key, void *value);
int hash_item_delete(thash *hash, const void *key);
thash *hash_new(unsigned n_buckets, thash_func hash_func, tequal_func equal_func);
thash *hash_new_ext(unsigned n_buckets,
                    thash_func hash_func,
                    tequal_func equal_func,
                    tfree_func key_free_func,
                    tfree_func value_free_func);
void hash_set_value_free_func(thash *hash, tfree_func value_free_func);
int hash_iterate(thash *hash, titerate_func iterate_func, void *arg);
uint64_t hash_count_items(thash *hash);
void hash_fill(thash *to, thash *from);
void hash_fill_and_reset(thash *to, thash *from);
void hash_drain(thash *hash);
void hash_free(thash *hash);

#endif /* __HASH_H__ */
