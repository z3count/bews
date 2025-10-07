#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "list.h"


typedef struct node {
        void *elem;
        struct node *next;
} tnode;

struct list {
        tnode *head;
        tnode *tail;

        int size;

        tlist_free_func free_func;
        tlist_cmp_func cmp_func;
};

void list_free(tlist *q)
{
        if (! q)
                return;

        tnode *node = q->head;

        while (node) {
                tnode *dummy = node;
                node = node->next;
                q->free_func(dummy->elem);
                free(dummy);
        }

        free(q);
}

static int list_default_cmp(void *a, void *b)
{
        if ((uintptr_t) a < (uintptr_t) b)
                return -1;

        if ((uintptr_t) a > (uintptr_t) b)
                return 1;

        return 0;
}

tlist *list_new(void)
{
        tlist *q = malloc(sizeof *q);
        if (! q)
                return NULL;

        q->head = NULL;
        q->tail = NULL;
        q->size = 0;

        /* default: the stdlib free() function */
        q->free_func = free;
        q->cmp_func = list_default_cmp;

        return q;
}

void list_set_free_func(tlist *list, tlist_free_func free_func)
{
        list->free_func = free_func;
}

void list_set_cmp_func(tlist *list, tlist_cmp_func cmp_func)
{
        list->cmp_func = cmp_func;
}

int list_get_size(tlist *q)
{
        if (! q)
                return -1;

        return q->size;
}

void list_add_tail(tlist *q, void *elem)
{
        tnode *node;

        if (! elem)
                return;

        if (NULL == (node = malloc(sizeof *node))) {
                perror("malloc");
                return;
        }

        node->elem = elem;
        node->next = NULL;

        if (! q->head)
                list_add(q, elem);
        else {
                q->tail->next = node;
                q->tail = node;
                q->size++;
        }
}

void list_add(tlist *q, void *elem)
{
        if (! elem)
                return;

        tnode *node = malloc(sizeof *node);
        if (! node) {
                perror("malloc");
                return;
        }

        /* first add */
        if (! q->tail)
                q->tail = node;

        node->next = q->head;
        node->elem = elem;
        q->head = node;

        q->size++;
}

void list_add_sorted(tlist *q, void *elem)
{
        if (! q)
                return;

        if (! elem)
                return;

        tnode *prev = NULL;
        tnode *head = q->head;

        if (! head || ! head->elem)
                return list_add_tail(q, elem);

        while (head && head->elem) {
                if (q->cmp_func(elem, head->elem) < 0) {

                        /* prepend at the head of the list */
                        if (! prev)
                                return list_add(q, elem);

                        tnode *node = malloc(sizeof *node);
                        if (! node) {
                                perror("malloc");
                                return;
                        }

                        /* insert between prev and head */
                        node->elem = elem;
                        prev->next = node;
                        node->next = head;
                        q->size++;

                        return;
                }

                prev = head;
                head = head->next;
        }


        /* append at the end of the list */
        list_add_tail(q, elem);
}

void *list_get(tlist *q, void *key)
{
        if (! q || 0 == q->size)
                return NULL;

        tnode *node = q->head;

        while (node) {
                if (0 == q->cmp_func(key, node->elem))
                        return node->elem;

                node = node->next;
        }

        return NULL;
}

void *list_get_nth(tlist *q, int n)
{
        if (! q || n >= q->size)
                return NULL;

        tnode *node = q->head;

        while (n > 0) {
                node = node->next;
                n--;
        }

        return node->elem;
}

/* if we don't want any duplicate, use this function (slow) */
int list_add_uniq(tlist *q, void *elem)
{
        if (! elem)
                return -1;

        if (list_get(q, elem))
                return -1;

        list_add(q, elem);

        return 0;
}

void list_map_internal(tnode *head, tlist_map_func map_func, void *ctx)
{
        if (! head)
                return;

        if (head->elem)
                map_func(head->elem, ctx);

        list_map_internal(head->next, map_func, ctx);
}


void list_map(tlist *q, tlist_map_func map_func, void *ctx)
{
        if (q)
                list_map_internal(q->head, map_func, ctx);
}
