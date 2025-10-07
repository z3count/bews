#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "tpool.h"


#define MAX(a, b) ((a) > (b) ? (a) : (b))

typedef ttask *(*ttask_get_func)(struct stask_pool *pool);
typedef int (*ttask_put_func)(struct stask_pool *pool, ttask *task);
typedef void (*ttask_delete_func)(struct stask_pool *pool, ttask *task);

struct stask_pool
{
        pthread_cond_t task_cond;
        pthread_cond_t idle_cond;
        pthread_mutex_t task_lock;

        int n_workers;                      /* total workers: idling+working */
        int n_workers_needed;
        int n_workers_running;
        int n_workers_min;

        int n_tasks;                        /* remaining tasks to manage */
        ttask *task_queue;
        ttask *task_last;

        ttask_get_func task_get_func;       /* get the first task available */
        ttask_put_func task_put_func;       /* add a new task to the queue*/
        ttask_delete_func task_delete_func; /* remove a task from the queue */

        pthread_attr_t attr;
        int stopped;
};

static void ttask_pool_delete_func(ttask_pool *pool, ttask *task)
{
        (void) pool;
        (void) task;
}

void task_pool_set_delete_func(ttask_pool *pool, ttask_delete_func delete_func)
{
        pool->task_delete_func = delete_func;
}

static ttask *ttask_pool_get_func(ttask_pool *pool)
{
        ttask *task;

        if (! pool->task_queue)
                return NULL;

        task = pool->task_queue;
        pool->task_queue = task->next;
        if (! pool->task_queue)
                pool->task_last = NULL;

        return task;
}

static int ttask_pool_put_func(ttask_pool *pool, ttask *task)
{
        task->next = NULL;

        if (! pool->task_queue) {
                pool->task_queue = pool->task_last = task;
        } else {
                pool->task_last->next = task;
                pool->task_last = task;
        }

        return 0;
}

ttask *ttask_pool_get(ttask_pool *pool)
{
        ttask *task = NULL;

        pthread_mutex_lock(&pool->task_lock);

        while (1) {
                if (pool->n_workers <= pool->n_workers_needed) {
                        if ((task = pool->task_get_func(pool))) {
                                pool->n_tasks--;
                                break;
                        }
                }

                pool->n_workers_running--;
                pthread_cond_broadcast(&pool->idle_cond);

                if (pool->stopped || pool->n_workers > pool->n_workers_needed) {
                        pool->n_workers--;
                        pthread_cond_broadcast(&pool->task_cond);
                        pthread_mutex_unlock(&pool->task_lock);
                        pthread_exit(NULL);
                }

                pthread_cond_wait(&pool->task_cond, &pool->task_lock);
                pool->n_workers_running++;
        }

        pthread_mutex_unlock(&pool->task_lock);

        return task;
}

int ttask_pool_put(ttask_pool *pool, ttask *task)
{
        int ret, rc;

        pthread_mutex_lock(&pool->task_lock);

        if ((rc = pool->task_put_func(pool, task))) {
                ret = rc;
                goto end;
        }

        pool->n_tasks++;

        pthread_cond_signal(&pool->task_cond);

        ret = 0;
  end:
        pthread_mutex_unlock(&pool->task_lock);

        return ret;
}

static void *worker_main(void *arg)
{
        ttask_pool *pool = arg;

        pthread_mutex_lock(&pool->task_lock);
        pool->n_workers_running++;
        pthread_mutex_unlock(&pool->task_lock);

        while (1) {
                ttask *task;

                task = ttask_pool_get(pool);
                assert(NULL != task);

                task->func(task);

                pthread_mutex_lock(&pool->task_lock);
                pool->task_delete_func(pool, task);
                pthread_mutex_unlock(&pool->task_lock);
        }

        return NULL;
}

static void ttask_pool_stop(ttask_pool *pool)
{
        pthread_mutex_lock(&pool->task_lock);

        pool->stopped = 1;
        pthread_cond_broadcast(&pool->task_cond);

        while (pool->n_workers)
                pthread_cond_wait(&pool->task_cond, &pool->task_lock);

        pthread_mutex_unlock(&pool->task_lock);
}

static void ttask_pool_wait_idle(ttask_pool *pool)
{
        pthread_mutex_lock(&pool->task_lock);

        /* some tasks are waiting to be handled, or some threads are running */
        while (pool->n_tasks || pool->n_workers_running)
                pthread_cond_wait(&pool->idle_cond, &pool->task_lock);

        pthread_mutex_unlock(&pool->task_lock);
}

static void ttask_pool_dtor(ttask_pool *pool)
{
        ttask_pool_wait_idle(pool);

        if (! pool->stopped)
                ttask_pool_stop(pool);

        pthread_attr_destroy(&pool->attr);
        pthread_mutex_destroy(&pool->task_lock);
        pthread_cond_destroy(&pool->task_cond);
        pthread_cond_destroy(&pool->idle_cond);
}

int ttask_pool_ctor(ttask_pool *pool, int n_workers)
{
        if (! pool)
                goto bad;

        if (n_workers <= 0)
                n_workers = DEFAULT_N_WORKERS;

        memset(pool, 0, sizeof *pool);

        if (pthread_attr_init(&pool->attr))
                goto bad;

        pthread_attr_setdetachstate(&pool->attr, PTHREAD_CREATE_DETACHED);

        pool->n_tasks = 0;
        pool->stopped = 0;

        pool->n_workers = 0;
        pool->n_workers_min = 0;
        pool->n_workers_needed = n_workers;

        pool->task_get_func = ttask_pool_get_func;
        pool->task_put_func = ttask_pool_put_func;
        pool->task_delete_func = ttask_pool_delete_func;

        pool->task_queue = NULL;
        pool->task_last = NULL;

        pthread_mutex_init(&pool->task_lock, NULL);
        pthread_cond_init(&pool->task_cond, NULL);
        pthread_cond_init(&pool->idle_cond, NULL);

        if (ttask_pool_set_workers(pool, n_workers)) {
                ttask_pool_dtor(pool);
                goto bad;
        }

        return 0;
  bad:
        return -1;
}

ttask_pool *ttask_pool_create(int n_workers)
{
        ttask_pool *pool = NULL;

        if (NULL == (pool = calloc(1, sizeof *pool)))
                goto bad;

        if (ttask_pool_ctor(pool, n_workers))
                goto bad;

        return pool;

  bad:
        if (pool)
                ttask_pool_dtor(pool);

        free(pool);

        return NULL;
}

void ttask_pool_free(ttask_pool *pool)
{
        if (pool)
                ttask_pool_dtor(pool);
        free(pool);
}

int ttask_pool_set_workers_min(ttask_pool *pool, int n_workers_min)
{
        if (n_workers_min < 0)
                return -1;

        pthread_mutex_lock(&pool->task_lock);
        pool->n_workers_min = n_workers_min;
        pthread_mutex_unlock(&pool->task_lock);

        return 0;
}

int ttask_pool_set_workers(ttask_pool *pool, int n_workers_needed)
{
        int i, ret = 0;

        if (n_workers_needed < 0)
                return -1;

        pthread_mutex_lock(&pool->task_lock);

        n_workers_needed = MAX(n_workers_needed, pool->n_workers_min);
        pool->n_workers_needed = n_workers_needed;

        while (! pool->n_workers_needed && pool->n_tasks)
                pthread_cond_wait(&pool->idle_cond, &pool->task_lock);

        if (n_workers_needed < pool->n_workers) {
                pthread_cond_broadcast(&pool->task_cond);
        } else {
                for (i = pool->n_workers; i < n_workers_needed; i++) {
                        pthread_t tid;
                        ret = pthread_create(&tid, &pool->attr, worker_main, pool);
                        if (0 ==  ret)
                                pool->n_workers++;
                        else
                                break;
                }
        }

        pthread_mutex_unlock(&pool->task_lock);

        if (ret)
                return -1;

        return 0;
}
