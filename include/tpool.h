#ifndef TPOOL_H
#define TPOOL_H

#define DEFAULT_N_WORKERS 10

typedef void (*ttask_func)(void *arg);

/* self-embedded structure... add it to the one you want to manage */
typedef struct stask
{
        struct stask *next;
        ttask_func  func;
} ttask;

typedef struct stask_pool ttask_pool;

typedef void (*ttask_delete_func)(ttask_pool *, ttask *);

ttask_pool *ttask_pool_create(int n_workers);
void ttask_pool_free(ttask_pool *pool);

void task_pool_set_delete_func(ttask_pool *pool, ttask_delete_func delete_func);
int ttask_pool_set_workers_min(ttask_pool *pool, int n_workers_min);
int ttask_pool_set_workers(ttask_pool *pool, int n_workers_needed);

int ttask_pool_put(ttask_pool *pool, ttask *task);
ttask *ttask_pool_get(ttask_pool *pool);




#endif /* TPOOL_H */
