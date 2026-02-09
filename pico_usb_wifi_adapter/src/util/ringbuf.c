#include "ringbuf.h"

#include <string.h>

void ringbuf_init(ringbuf_t* rb, uint8_t* storage, size_t cap) {
    rb->buf = storage;
    rb->cap = cap;
    rb->r = rb->w = rb->len = 0;
}

size_t ringbuf_available(const ringbuf_t* rb) {
    return rb->len;
}

size_t ringbuf_write(ringbuf_t* rb, const uint8_t* data, size_t n) {
    size_t wrote = 0;
    while (wrote < n && rb->len < rb->cap) {
        rb->buf[rb->w] = data[wrote++];
        rb->w = (rb->w + 1) % rb->cap;
        rb->len++;
    }
    return wrote;
}

size_t ringbuf_peek(const ringbuf_t* rb, size_t off, uint8_t* out, size_t n) {
    if (off + n > rb->len) return 0;
    size_t idx = (rb->r + off) % rb->cap;
    for (size_t i = 0; i < n; i++) {
        out[i] = rb->buf[idx];
        idx = (idx + 1) % rb->cap;
    }
    return n;
}

size_t ringbuf_read(ringbuf_t* rb, uint8_t* out, size_t n) {
    size_t rd = 0;
    while (rd < n && rb->len > 0) {
        out[rd++] = rb->buf[rb->r];
        rb->r = (rb->r + 1) % rb->cap;
        rb->len--;
    }
    return rd;
}
