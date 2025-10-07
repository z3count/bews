#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "queue.h"
#include "hash.h"

typedef struct shash_item
{
        SLIST_ENTRY(shash_item) next_items;
        void *key;
        void *value;
} thash_item;

struct shash {
        SLIST_HEAD(shash_item_list, shash_item) *buckets;
        tfree_func key_free_func;
        tfree_func value_free_func;
        thash_func hash_func;
        tequal_func equal_func;
        unsigned n_buckets;
        size_t size;
        size_t n_items;
};

typedef struct shash_item_list thash_item_list;

unsigned int generic_buffer_hashcode(const unsigned char *buf, size_t len)
{
        const unsigned char *p = NULL;
        unsigned h, g;
        size_t i = 0;

        h = g = 0;

        for (p = buf; i < len; p++, i++) {
                h = (h << 4) + *p;
                if ((g = h & 0xf0000000)) {
                        h = h ^ (g >> 24);
                        h = h ^ g;
                }
        }

        return h;
}

unsigned int string_hashcode(const void *data)
{
        return generic_buffer_hashcode(data, strlen(data));
}

static thash_item_list *get_bucket(thash *hash, const void *key)
{
        return &hash->buckets[hash->hash_func(key) % hash->n_buckets];
}

size_t hash_sizeof(thash *hash)
{
        return hash->size;
}

size_t hash_get_n_items(thash *hash)
{
        return hash->n_items;
}

static thash_item *hash_item_get_internal(thash *hash, const void *key)
{
        thash_item *item = NULL;

        SLIST_FOREACH(item, get_bucket(hash, key), next_items)
                if (hash->equal_func(item->key, key))
                        return item;

        return NULL;
}

static int hash_item_put_internal(thash *hash, void *key, void *value)
{
        thash_item_list *bucket = NULL;
        thash_item *item = NULL;

        if (NULL == (item = calloc(1, sizeof *item)))
                return HASH_ENOMEM;

        item->key = key;
        item->value = value;
        bucket = get_bucket(hash, key);
        SLIST_INSERT_HEAD(bucket, item, next_items);

        hash->size += sizeof *item;

        return HASH_SUCCESS;
}

int hash_item_put(thash *hash, void *key, void *value)
{
        thash_item *item = NULL;

        if ((item = hash_item_get_internal(hash, key)))
                return HASH_EEXIST;

        return hash_item_put_internal(hash, key, value);
}

void *hash_item_get(thash *hash, const void *key)
{
        thash_item *item = NULL;

        item = hash_item_get_internal(hash, key);
        return item ? item->value : NULL;
}

int hash_item_update(thash *hash, void *key, void *value)
{
        thash_item *item = NULL;

        if (NULL == (item = hash_item_get_internal(hash, key)))
                return HASH_ENOENT;

        if (hash->key_free_func)
                hash->key_free_func(item->key);

        if (hash->value_free_func)
                hash->value_free_func(item->value);

        item->key = key;
        item->value = value;

        return HASH_SUCCESS;
}

int hash_item_set(thash *hash, void *key, void *value)
{
        int ret;

        ret = hash_item_update(hash, key, value);
        if (HASH_ENOENT == ret)
                ret = hash_item_put_internal(hash, key, value);

        return ret;
}


int hash_item_delete(thash *hash, const void *key)
{
        thash_item *item = NULL;

        if (NULL == (item = hash_item_get_internal(hash, key)))
                return HASH_ENOENT;

        SLIST_REMOVE(get_bucket(hash, item->key), item, shash_item, next_items);

        if (hash->key_free_func)
                hash->key_free_func(item->key);

        if (hash->value_free_func)
                hash->value_free_func(item->value);


        free(item);
        hash->size -= sizeof *item;
        hash->n_items--;

        return HASH_SUCCESS;
}

thash *hash_new(unsigned n_buckets, thash_func hash_func,
                tequal_func equal_func)
{
        return hash_new_ext(n_buckets, hash_func, equal_func, NULL, NULL);

}

thash *hash_new_ext(unsigned n_buckets, thash_func hash_func,
                    tequal_func equal_func, tfree_func key_free_func,
                    tfree_func value_free_func)
{
        thash *hash = NULL;

        if (NULL == (hash = calloc(1, sizeof *hash)))
                goto bad;

        if (0 == n_buckets)
                n_buckets = 511;

        if (NULL == (hash->buckets = malloc(n_buckets * sizeof *hash->buckets)))
                goto bad;

        for (unsigned i = 0; i < n_buckets; i++)
                SLIST_INIT(&hash->buckets[i]);

        hash->n_buckets = n_buckets;
        hash->hash_func = hash_func;
        hash->equal_func = equal_func;
        hash->key_free_func = key_free_func;
        hash->value_free_func = value_free_func;
        hash->n_items = 0;
        hash->size = sizeof *hash +
                (size_t) (hash->n_buckets - 1) * sizeof *hash->buckets;

        return hash;
  bad:
        if (hash)
                free(hash->buckets);
        free(hash);

        return NULL;
}

void hash_set_value_free_func(thash *hash, tfree_func value_free_func)
{
        hash->value_free_func = value_free_func;
}

int hash_iterate(thash *hash, titerate_func iterate_func, void *data)
{
        thash_item *item = NULL;
        thash_item *prev = NULL;
        int ret;

        for (unsigned bucket = 0; bucket < hash->n_buckets; bucket++) {
                SLIST_FOREACH_SAFE(item, &hash->buckets[bucket],
                                   next_items, prev) {
                        if ((ret = iterate_func(item->key, item->value, data)))
                                return ret;
                }
        }

        return 0;
}


struct fill_iter {
        thash *from;
        thash *to;
        int do_remove;
};

static int hash_fill_cb(const void *key, const void *value, void *cb_arg)
{
        struct fill_iter *it = cb_arg;

        (void) hash_item_put(it->to, (void *) key, (void *) value);

        if (it->do_remove) {
                thash_item *item = hash_item_get_internal(it->from, key);
                assert(item);

                SLIST_REMOVE(get_bucket(it->from, item->key),
                             item,
                             shash_item,
                             next_items);

                free(item);
                it->from->n_items--;
                it->from->size -= sizeof (thash_item);
        }

        return 0;
}

static void hash_fill_ext(thash *to, thash *from, int do_remove)
{
        struct fill_iter it;

        it.from = from;
        it.to = to;
        it.do_remove = do_remove;

        (void) hash_iterate(from, hash_fill_cb, &it);
}

void hash_fill(thash *to, thash *from)
{
        hash_fill_ext(to, from, 0);
}

void hash_fill_and_reset(thash *to, thash *from)
{
        hash_fill_ext(to, from, 1);
}

static void hash_drain_internal(thash *hash)
{
        thash_item *item = NULL;
        thash_item *prev = NULL;

        for (unsigned bucket = 0; bucket < hash->n_buckets; bucket++) {
                SLIST_FOREACH_SAFE(item,
                                   &hash->buckets[bucket],
                                   next_items,
                                   prev) {
                        if (hash->key_free_func)
                                hash->key_free_func(item->key);

                        if (hash->value_free_func)
                                hash->value_free_func(item->value);

                        free(item);
                        hash->size -= sizeof *item;
                        hash->n_items--;
                }
        }
}

void hash_drain(thash *hash)
{
        hash_drain_internal(hash);
        memset(hash->buckets, 0, hash->n_buckets * sizeof *hash->buckets);
}

void hash_free(thash *hash)
{
        if (! hash)
                return;

        hash_drain_internal(hash);
        free(hash->buckets);
        free(hash);
}

static int hash_count_cb(const void *key, const void *value, void *user_data)
{
        uint64_t *count = user_data;

        (void) key;
        (void) value;

        (*count)++;

        return 0;
}

uint64_t hash_count_items(thash *hash)
{
        uint64_t count = 0;
        (void) hash_iterate(hash, hash_count_cb, &count);

        return count;
}
