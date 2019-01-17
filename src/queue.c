#include "queue.h"

#include <stdlib.h>

struct ll_obj {
	struct list_head head;
	void *command;
};

void queue_init(struct queue *q) {
	INIT_LIST_HEAD(&q->list);
	pthread_mutex_init(&q->mutex, NULL);
	pthread_cond_init(&q->cond, NULL);
}

void queue_destroy(struct queue *q) {
	pthread_mutex_destroy(&q->mutex);
	pthread_cond_destroy(&q->cond);
}

void enqueue(struct queue *q, void *command) {
	struct ll_obj *ll = calloc(1, sizeof(struct ll_obj));
	ll->command = command;

	pthread_mutex_lock(&q->mutex);
	list_add(&ll->head, &q->list);
	pthread_mutex_unlock(&q->mutex);
	pthread_cond_broadcast(&q->cond);
}

static int _dequeue(struct queue *q, void **cmd, bool wait) {
	struct ll_obj *ll;
	struct list_head *header;
	int rc = -1;
	void *command;

	pthread_mutex_lock(&q->mutex);
	if (list_empty(&q->list)) {
		if (wait)
			rc = pthread_cond_wait(&q->cond, &q->mutex);

		if (rc == 0)
			pthread_mutex_unlock(&q->mutex);

		return -1;
	}

	ll = calloc(1, sizeof(struct ll_obj));

	header = q->list.prev;
	list_del(header);
	pthread_mutex_unlock(&q->mutex);

	ll = container_of(header, struct ll_obj, head);
	command = ll->command;
	free(ll);

	*cmd = command;

	return 0;
}

int dequeue(struct queue *q, void **cmd) {
	return _dequeue(q, cmd, true);
}

void queue_flush(struct queue *q) {
	void *cmd;
	while (_dequeue(q, &cmd, false) == 0)
		free(cmd);
}
