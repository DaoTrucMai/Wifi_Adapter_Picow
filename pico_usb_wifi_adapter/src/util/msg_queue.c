#include "msg_queue.h"

#include <string.h>

void mq_init(msg_queue_t* mq) {
    mq->r = mq->w = mq->count = 0;
}

bool mq_is_empty(const msg_queue_t* mq) {
    return mq->count == 0;
}

bool mq_push(msg_queue_t* mq, const uint8_t* data, uint16_t len) {
    if (len > MQ_MAX_MSG) return false;
    if (mq->count >= MQ_DEPTH) return false;

    mq_msg_t* m = &mq->q[mq->w];
    m->len = len;
    memcpy(m->data, data, len);

    mq->w = (mq->w + 1) % MQ_DEPTH;
    mq->count++;
    return true;
}

bool mq_push2(msg_queue_t* mq, const void* data1, uint16_t len1, const void* data2, uint16_t len2) {
    uint16_t total_len = len1 + len2;
    if (total_len > MQ_MAX_MSG) return false;
    if (mq->count >= MQ_DEPTH) return false;

    mq_msg_t* m = &mq->q[mq->w];
    m->len = total_len;
    memcpy(m->data, data1, len1);
    memcpy(m->data + len1, data2, len2);

    mq->w = (mq->w + 1) % MQ_DEPTH;
    mq->count++;
    return true;
}

bool mq_pop(msg_queue_t* mq, uint8_t* out, uint16_t* out_len) {
    if (mq->count == 0) return false;

    mq_msg_t* m = &mq->q[mq->r];
    memcpy(out, m->data, m->len);
    *out_len = m->len;

    mq->r = (mq->r + 1) % MQ_DEPTH;
    mq->count--;
    return true;
}

bool mq_drop(msg_queue_t* mq) {
    if (mq->count == 0) return false;
    mq->r = (mq->r + 1) % MQ_DEPTH;
    mq->count--;
    return true;
}
