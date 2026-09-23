#include "entropy_fill.h"
#include <string.h>
int radio_entropy_fill(unsigned char *out, size_t len, size_t *olen,
                       radio_rng_word word, void *ctx) {
    if (olen) *olen = 0;
    if (!out) return -1;
    size_t filled = 0;
    while (filled < len) {
        uint64_t value;
        if (word(ctx, &value) != 0) return -1;
        size_t chunk = len - filled;
        if (chunk > 8) chunk = 8;
        memcpy(out + filled, &value, chunk);
        filled += chunk;
    }
    if (olen) *olen = filled;
    return 0;
}
