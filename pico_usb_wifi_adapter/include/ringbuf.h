#ifndef RINGBUF_H
#define RINGBUF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t* buf;
    size_t cap;
    size_t r;
    size_t w;
    size_t len;
} ringbuf_t;

void ringbuf_init(ringbuf_t* rb, uint8_t* storage, size_t cap);
size_t ringbuf_write(ringbuf_t* rb, const uint8_t* data, size_t n);
size_t ringbuf_peek(const ringbuf_t* rb, size_t off, uint8_t* out, size_t n);
size_t ringbuf_read(ringbuf_t* rb, uint8_t* out, size_t n);
size_t ringbuf_available(const ringbuf_t* rb);

#endif
