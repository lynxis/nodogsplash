#ifndef QUEUE_H
#define QUEUE_H

#include <pthread.h>

#include "list.h"

struct queue {
	struct list_head list;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
};

void queue_init(struct queue *queue);
void enqueue(struct queue *queue, void *command);
int dequeue(struct queue *queue, void **cmd);
void queue_flush(struct queue *queue);

#endif // QUEUE_H
