#ifndef MSG_QUEUE_H
#define MSG_QUEUE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MQ_MAX_MSG 2048
#define MQ_DEPTH 32

typedef struct {
    uint16_t len;
    uint8_t data[MQ_MAX_MSG];
} mq_msg_t;

typedef struct {
    mq_msg_t q[MQ_DEPTH];
    uint8_t r;
    uint8_t w;
    uint8_t count;
} msg_queue_t;

void mq_init(msg_queue_t* mq);
bool mq_push(msg_queue_t* mq, const uint8_t* data, uint16_t len);
bool mq_pop(msg_queue_t* mq, uint8_t* out, uint16_t* out_len);
// Drops the oldest message without copying it out.
bool mq_drop(msg_queue_t* mq);
bool mq_is_empty(const msg_queue_t* mq);

#endif
