#ifndef BRIDGE_CORE_H
#define BRIDGE_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BRIDGE_MAX_INPUT_BYTES 1024u
#define BRIDGE_MAX_STROKES (2u * BRIDGE_MAX_INPUT_BYTES)
#define BRIDGE_MAX_TTL_MS 15000u
#define BRIDGE_REPLAY_CAPACITY 64u
#define BRIDGE_FLAG_ALLOW_LF 0x01u
#define BRIDGE_FLAG_ALLOW_TAB 0x02u
#define BRIDGE_MOD_LEFT_SHIFT 0x02u
#define BRIDGE_MOD_RIGHT_ALT 0x40u

typedef enum { BRIDGE_LAYOUT_US = 1, BRIDGE_LAYOUT_DE = 2 } bridge_layout_t;
typedef enum { BRIDGE_MODE_PASSWORD = 1, BRIDGE_MODE_TEXT = 2 } bridge_mode_t;
typedef enum {
    BRIDGE_OK = 0,
    BRIDGE_DONE,
    BRIDGE_ERR_ARGUMENT,
    BRIDGE_ERR_STATE,
    BRIDGE_ERR_BUSY,
    BRIDGE_ERR_LIMIT,
    BRIDGE_ERR_UTF8,
    BRIDGE_ERR_UNSUPPORTED,
    BRIDGE_ERR_POLICY,
    BRIDGE_ERR_OWNER,
    BRIDGE_ERR_ID,
    BRIDGE_ERR_EXPIRED,
    BRIDGE_ERR_REPLAY
} bridge_status_t;
typedef enum {
    BRIDGE_STATE_EMPTY = 0,
    BRIDGE_STATE_STAGED,
    BRIDGE_STATE_EXECUTING,
    BRIDGE_STATE_COMPLETED,
    BRIDGE_STATE_CANCELLED,
    BRIDGE_STATE_EXPIRED,
    BRIDGE_STATE_REJECTED
} bridge_state_t;

typedef struct { uint8_t modifier; uint8_t usage; } bridge_stroke_t;

/* Static allocation, no allocator or platform dependencies. Fields are read-only
 * to callers; never serialize this structure or expose strokes in logs/status.
 * A single trusted scheduler must serialize all calls. No concurrent access. */
typedef struct {
    size_t replay_count;
    struct { uint32_t owner; uint32_t id; } replay[BRIDGE_REPLAY_CAPACITY];
    bridge_state_t state;
    uint32_t owner;
    uint32_t id;
    uint32_t staged_at_ms;
    uint32_t ttl_ms;
    bridge_layout_t layout;
    bridge_mode_t mode;
    uint8_t flags;
    size_t stroke_count;
    size_t cursor;
    bridge_stroke_t strokes[BRIDGE_MAX_STROKES];
} bridge_core_t;

void bridge_core_init(bridge_core_t *core);
bridge_status_t bridge_core_stage(bridge_core_t *core, uint32_t owner, uint32_t id,
                                 bridge_layout_t layout, bridge_mode_t mode,
                                 uint8_t flags, const uint8_t *utf8, size_t length,
                                 uint32_t now_ms, uint32_t ttl_ms);
bridge_status_t bridge_core_confirm(bridge_core_t *core, uint32_t owner,
                                   uint32_t id, uint32_t now_ms);
bridge_status_t bridge_core_next(bridge_core_t *core, uint32_t now_ms,
                                bridge_stroke_t *stroke);
bridge_status_t bridge_core_tick(bridge_core_t *core, uint32_t now_ms);
bridge_status_t bridge_core_cancel(bridge_core_t *core, uint32_t owner, uint32_t id);
/* Trusted local abort on disconnect, USB failure, lock change, etc. */
void bridge_core_abort(bridge_core_t *core);

#ifdef __cplusplus
}
#endif
#endif
