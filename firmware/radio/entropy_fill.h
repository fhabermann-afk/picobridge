#ifndef RADIO_ENTROPY_FILL_H
#define RADIO_ENTROPY_FILL_H
#include <stddef.h>
#include <stdint.h>
typedef int (*radio_rng_word)(void *,uint64_t *);
int radio_entropy_fill(unsigned char *out,size_t len,size_t *olen,radio_rng_word word,void *ctx);
#endif
