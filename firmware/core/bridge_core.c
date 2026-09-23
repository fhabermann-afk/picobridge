#include "bridge_core.h"
#include <string.h>

static void wipe(void *memory, size_t length)
{
    volatile unsigned char *p = memory;
    while (length--) *p++ = 0;
}

static void terminate(bridge_core_t *core, bridge_state_t state)
{
    /* The non-secret replay ledger is outside the wiped job region. */
    wipe((unsigned char *)core + offsetof(bridge_core_t, state),
         sizeof *core - offsetof(bridge_core_t, state));
    core->state = state;
}

static bridge_status_t reject(bridge_core_t *core, bridge_status_t status)
{
    terminate(core, BRIDGE_STATE_REJECTED);
    return status;
}

static bridge_status_t decode_utf8(const uint8_t *input, size_t length,
                                   size_t *offset, uint32_t *cp)
{
    uint8_t lead = input[(*offset)++];
    unsigned continuation;
    uint32_t minimum;
    if (lead < 0x80) { *cp = lead; return BRIDGE_OK; }
    if (lead >= 0xc2 && lead <= 0xdf) {
        *cp = lead & 0x1f; continuation = 1; minimum = 0x80;
    } else if (lead >= 0xe0 && lead <= 0xef) {
        *cp = lead & 0x0f; continuation = 2; minimum = 0x800;
    } else if (lead >= 0xf0 && lead <= 0xf4) {
        *cp = lead & 0x07; continuation = 3; minimum = 0x10000;
    } else return BRIDGE_ERR_UTF8;
    if (length - *offset < continuation) return BRIDGE_ERR_UTF8;
    for (unsigned i = 0; i < continuation; ++i) {
        uint8_t byte = input[(*offset)++];
        if ((byte & 0xc0) != 0x80) return BRIDGE_ERR_UTF8;
        *cp = (*cp << 6) | (byte & 0x3f);
    }
    if (*cp < minimum || *cp > 0x10ffff || (*cp >= 0xd800 && *cp <= 0xdfff))
        return BRIDGE_ERR_UTF8;
    return BRIDGE_OK;
}

static bridge_status_t map_ascii(uint32_t cp, bridge_stroke_t *stroke)
{
    static const char plain[] = "`1234567890-=[]\\;',./";
    static const char shifted[] = "~!@#$%^&*()_+{}|:\"<>?";
    static const uint8_t usages[] = {
        53,30,31,32,33,34,35,36,37,38,39,45,46,47,48,49,51,52,54,55,56
    };
    stroke->modifier = 0;
    if (cp >= 'a' && cp <= 'z') {
        stroke->usage = (uint8_t)(cp - 'a' + 4);
        return BRIDGE_OK;
    }
    if (cp >= 'A' && cp <= 'Z') {
        stroke->modifier = BRIDGE_MOD_LEFT_SHIFT;
        stroke->usage = (uint8_t)(cp - 'A' + 4);
        return BRIDGE_OK;
    }
    if (cp == ' ') {
        stroke->usage = 44;
        return BRIDGE_OK;
    }
    for (size_t i = 0; i < sizeof usages; ++i) {
        if (cp == (uint8_t)plain[i] || cp == (uint8_t)shifted[i]) {
            stroke->usage = usages[i];
            stroke->modifier = cp == (uint8_t)shifted[i] ? BRIDGE_MOD_LEFT_SHIFT : 0;
            return BRIDGE_OK;
        }
    }
    return BRIDGE_ERR_UNSUPPORTED;
}

static bridge_status_t map_de(uint32_t cp, bridge_stroke_t *stroke)
{
    static const char symbols[] = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
    static const bridge_stroke_t keys[] = {
        {2,30},{2,31},{0,50},{2,33},{2,34},{2,35},{2,50},{2,37},{2,38},
        {2,48},{0,48},{0,54},{0,56},{0,55},{2,36},{2,55},{2,54},
        {0,100},{2,39},{2,100},{2,45},{64,20},{64,37},{64,45},{64,38},
        {0,53},{2,56},{2,46},{64,36},{64,100},{64,39},{64,48}
    };
    _Static_assert(sizeof symbols - 1 == sizeof keys / sizeof keys[0], "DE map size");
    for (size_t i = 0; i < sizeof symbols - 1; ++i) {
        if (cp == (uint8_t)symbols[i]) { *stroke = keys[i]; return BRIDGE_OK; }
    }
    static const struct { uint32_t cp; bridge_stroke_t stroke; } unicode[] = {
        {0xe4,{0,52}},{0xf6,{0,51}},{0xfc,{0,47}},
        {0xc4,{2,52}},{0xd6,{2,51}},{0xdc,{2,47}},
        {0xdf,{0,45}},{0x20ac,{64,8}},{0xb4,{0,46}}
    };
    for (size_t i = 0; i < sizeof unicode / sizeof unicode[0]; ++i) {
        if (cp == unicode[i].cp) { *stroke = unicode[i].stroke; return BRIDGE_OK; }
    }
    if (cp == 'y') cp = 'z';
    else if (cp == 'Y') cp = 'Z';
    else if (cp == 'z') cp = 'y';
    else if (cp == 'Z') cp = 'Y';
    return map_ascii(cp, stroke);
}

void bridge_core_init(bridge_core_t *core)
{
    if (core != NULL) wipe(core, sizeof *core);
}

bridge_status_t bridge_core_stage(bridge_core_t *core, uint32_t owner, uint32_t id,
                                 bridge_layout_t layout, bridge_mode_t mode,
                                 uint8_t flags, const uint8_t *utf8, size_t length,
                                 uint32_t now_ms, uint32_t ttl_ms)
{
    if (core == NULL) return BRIDGE_ERR_ARGUMENT;
    if (core->state == BRIDGE_STATE_STAGED || core->state == BRIDGE_STATE_EXECUTING)
        return BRIDGE_ERR_BUSY;
    terminate(core, BRIDGE_STATE_EMPTY);
    if (length == 0 || length > BRIDGE_MAX_INPUT_BYTES)
        return reject(core, BRIDGE_ERR_LIMIT);
    if (utf8 == NULL || owner == 0 || id == 0 ||
        (layout != BRIDGE_LAYOUT_US && layout != BRIDGE_LAYOUT_DE) ||
        (mode != BRIDGE_MODE_PASSWORD && mode != BRIDGE_MODE_TEXT) ||
        ttl_ms == 0 || ttl_ms > BRIDGE_MAX_TTL_MS)
        return reject(core, BRIDGE_ERR_ARGUMENT);
    if ((flags & ~(BRIDGE_FLAG_ALLOW_LF | BRIDGE_FLAG_ALLOW_TAB)) != 0 ||
        (mode == BRIDGE_MODE_PASSWORD && flags != 0))
        return reject(core, BRIDGE_ERR_POLICY);
    for (size_t i = 0; i < core->replay_count; ++i) {
        if (core->replay[i].owner == owner && core->replay[i].id == id)
            return reject(core, BRIDGE_ERR_REPLAY);
    }
    if (core->replay_count == BRIDGE_REPLAY_CAPACITY) return reject(core, BRIDGE_ERR_LIMIT);
    core->owner = owner;
    core->id = id;
    core->layout = layout;
    core->mode = mode;
    core->flags = flags;
    core->staged_at_ms = now_ms;
    core->ttl_ms = ttl_ms;
    size_t offset = 0;
    while (offset < length) {
        uint32_t cp;
        bridge_status_t status = decode_utf8(utf8, length, &offset, &cp);
        if (status != BRIDGE_OK) return reject(core, status);
        if (cp == '\r' && mode == BRIDGE_MODE_TEXT &&
            (flags & BRIDGE_FLAG_ALLOW_LF) && offset < length && utf8[offset] == '\n') {
            ++offset;
            cp = '\n';
        }
        bridge_stroke_t *stroke = &core->strokes[core->stroke_count++];
        if (cp < 32 || cp == 127) {
            if (mode == BRIDGE_MODE_TEXT &&
                ((cp == '\n' && (flags & BRIDGE_FLAG_ALLOW_LF)) ||
                 (cp == '\t' && (flags & BRIDGE_FLAG_ALLOW_TAB)))) {
                stroke->usage = cp == '\n' ? 0x28 : 0x2b;
                continue;
            }
            return reject(core, BRIDGE_ERR_POLICY);
        }
        status = layout == BRIDGE_LAYOUT_DE ? map_de(cp, stroke) : map_ascii(cp, stroke);
        if (status != BRIDGE_OK) return reject(core, status);
        if (layout == BRIDGE_LAYOUT_DE && (cp == '^' || cp == '`' || cp == '~' || cp == 0xb4)) {
            core->strokes[core->stroke_count++].usage = 44;
        }
    }
    core->replay[core->replay_count].owner = owner;
    core->replay[core->replay_count].id = id;
    ++core->replay_count;
    core->state = BRIDGE_STATE_STAGED;
    return BRIDGE_OK;
}

void bridge_core_abort(bridge_core_t *core)
{
    if (core == NULL) return;
    terminate(core, BRIDGE_STATE_CANCELLED);
}

bridge_status_t bridge_core_cancel(bridge_core_t *core, uint32_t owner, uint32_t id)
{
    if (core == NULL) return BRIDGE_ERR_ARGUMENT;
    if (core->state != BRIDGE_STATE_STAGED && core->state != BRIDGE_STATE_EXECUTING)
        return BRIDGE_ERR_STATE;
    if (owner != core->owner) return BRIDGE_ERR_OWNER;
    if (id != core->id) return BRIDGE_ERR_ID;
    terminate(core, BRIDGE_STATE_CANCELLED);
    return BRIDGE_OK;
}

bridge_status_t bridge_core_tick(bridge_core_t *core, uint32_t now_ms)
{
    if (core == NULL) return BRIDGE_ERR_ARGUMENT;
    if (core->state == BRIDGE_STATE_STAGED &&
        (uint32_t)(now_ms - core->staged_at_ms) >= core->ttl_ms) {
        terminate(core, BRIDGE_STATE_EXPIRED);
        return BRIDGE_ERR_EXPIRED;
    }
    return BRIDGE_OK;
}

bridge_status_t bridge_core_confirm(bridge_core_t *core, uint32_t owner,
                                   uint32_t id, uint32_t now_ms)
{
    if (core == NULL) return BRIDGE_ERR_ARGUMENT;
    if (core->state != BRIDGE_STATE_STAGED) return BRIDGE_ERR_STATE;
    if (owner != core->owner) return BRIDGE_ERR_OWNER;
    if (id != core->id) return BRIDGE_ERR_ID;
    if (bridge_core_tick(core, now_ms) == BRIDGE_ERR_EXPIRED) return BRIDGE_ERR_EXPIRED;
    core->state = BRIDGE_STATE_EXECUTING;
    return BRIDGE_OK;
}

bridge_status_t bridge_core_next(bridge_core_t *core, uint32_t now_ms,
                                bridge_stroke_t *stroke)
{
    if (stroke != NULL) wipe(stroke, sizeof *stroke);
    if (core == NULL || stroke == NULL) return BRIDGE_ERR_ARGUMENT;
    if (bridge_core_tick(core, now_ms) == BRIDGE_ERR_EXPIRED) return BRIDGE_ERR_EXPIRED;
    if (core->state != BRIDGE_STATE_EXECUTING) return BRIDGE_ERR_STATE;
    if (core->cursor == core->stroke_count) {
        terminate(core, BRIDGE_STATE_COMPLETED);
        return BRIDGE_DONE;
    }
    *stroke = core->strokes[core->cursor];
    wipe(&core->strokes[core->cursor], sizeof *stroke);
    ++core->cursor;
    return BRIDGE_OK;
}
