#include "bridge_core.h"

#include <stdio.h>
#include <string.h>

static unsigned tests_run;
static unsigned failures;
#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "%s:%d: FAIL: %s\n", __func__, __LINE__, #expr); \
    ++failures; return; } } while (0)

static void stage_us_letter(void)
{
    bridge_core_t core;
    uint8_t input[] = {'a'};
    bridge_core_init(&core);
    CHECK(core.state == BRIDGE_STATE_EMPTY);
    CHECK(bridge_core_stage(&core, 7, 1, BRIDGE_LAYOUT_US,
                           BRIDGE_MODE_PASSWORD, 0, input, sizeof input,
                           100, 1000) == BRIDGE_OK);
    input[0] = 'z';
    CHECK(core.state == BRIDGE_STATE_STAGED);
    CHECK(core.owner == 7 && core.id == 1);
    CHECK(core.layout == BRIDGE_LAYOUT_US);
    CHECK(core.mode == BRIDGE_MODE_PASSWORD && core.flags == 0);
    CHECK(core.stroke_count == 1 && core.cursor == 0);
    CHECK(core.strokes[0].modifier == 0 && core.strokes[0].usage == 0x04);
}

static void us_printable_ascii(void)
{
    static const struct { const char *pair; uint8_t usage; } keys[] = {
        {"aA",4},{"bB",5},{"cC",6},{"dD",7},{"eE",8},{"fF",9},
        {"gG",10},{"hH",11},{"iI",12},{"jJ",13},{"kK",14},{"lL",15},
        {"mM",16},{"nN",17},{"oO",18},{"pP",19},{"qQ",20},{"rR",21},
        {"sS",22},{"tT",23},{"uU",24},{"vV",25},{"wW",26},{"xX",27},
        {"yY",28},{"zZ",29},{"1!",30},{"2@",31},{"3#",32},{"4$",33},
        {"5%",34},{"6^",35},{"7&",36},{"8*",37},{"9(",38},{"0)",39},
        {" ",44},{"-_",45},{"=+",46},{"[{",47},{"]}",48},{"\\|",49},
        {";:",51},{"\"",52},{"`~",53},{",<",54},{".>",55},{"/?",56},
        {"'",52}
    };
    unsigned count = 0;
    for (size_t i=0; i<sizeof keys/sizeof keys[0]; ++i) {
        for (size_t j=0; keys[i].pair[j]; ++j) {
            bridge_core_t core;
            uint8_t ch = (uint8_t)keys[i].pair[j];
            bridge_core_init(&core);
            CHECK(bridge_core_stage(&core,1,1,BRIDGE_LAYOUT_US,
                  BRIDGE_MODE_PASSWORD,0,&ch,1,0,100) == BRIDGE_OK);
            CHECK(core.stroke_count == 1);
            CHECK(core.strokes[0].usage == keys[i].usage);
            CHECK(core.strokes[0].modifier == ((j || ch == '"') ? 2 : 0));
            ++count;
        }
    }
    CHECK(count == 95);
}

static int payload_wiped(const bridge_core_t *core)
{
    const unsigned char *p = (const unsigned char *)core->strokes;
    for (size_t i=0; i<sizeof core->strokes; ++i) if (p[i]) return 0;
    return core->stroke_count == 0 && core->cursor == 0 && core->owner == 0 &&
           core->id == 0 && core->ttl_ms == 0 && core->staged_at_ms == 0 &&
           core->layout == 0 && core->mode == 0 && core->flags == 0;
}
static void rejected_preflight_wipes(void)
{
    bridge_core_t core;
    static const uint8_t good[] = "previous";
    static const uint8_t bad[] = {'n','e','w',0xc2,0xa3};
    bridge_core_init(&core);
    CHECK(bridge_core_stage(&core,1,1,BRIDGE_LAYOUT_US,BRIDGE_MODE_PASSWORD,
                           0,good,sizeof good-1,0,100) == BRIDGE_OK);
    bridge_stroke_t stroke;
    CHECK(bridge_core_confirm(&core,1,1,0) == BRIDGE_OK);
    for (size_t i=0; i<sizeof good-1; ++i)
        CHECK(bridge_core_next(&core,0,&stroke) == BRIDGE_OK);
    CHECK(bridge_core_next(&core,0,&stroke) == BRIDGE_DONE);
    CHECK(bridge_core_stage(&core,1,2,BRIDGE_LAYOUT_US,BRIDGE_MODE_PASSWORD,
                           0,bad,sizeof bad,0,100) == BRIDGE_ERR_UNSUPPORTED);
    CHECK(core.state == BRIDGE_STATE_REJECTED);
    CHECK(payload_wiped(&core));
}

static void bounded_request_validation(void)
{
    bridge_core_t core;
    uint8_t data[BRIDGE_MAX_INPUT_BYTES+1];
    memset(data,'a',sizeof data);
    struct invalid { uint32_t owner,id; bridge_layout_t layout; bridge_mode_t mode;
        uint8_t flags; const uint8_t *data; size_t len; uint32_t ttl;
        bridge_status_t status; };
    const struct invalid bad[] = {
        {1,1,BRIDGE_LAYOUT_US,BRIDGE_MODE_PASSWORD,0,data,0,1,BRIDGE_ERR_LIMIT},
        {1,1,BRIDGE_LAYOUT_US,BRIDGE_MODE_PASSWORD,0,data,sizeof data,1,BRIDGE_ERR_LIMIT},
        {1,1,BRIDGE_LAYOUT_US,BRIDGE_MODE_PASSWORD,0,data,SIZE_MAX,1,BRIDGE_ERR_LIMIT},
        {1,1,BRIDGE_LAYOUT_US,BRIDGE_MODE_PASSWORD,0,NULL,1,1,BRIDGE_ERR_ARGUMENT},
        {0,1,BRIDGE_LAYOUT_US,BRIDGE_MODE_PASSWORD,0,data,1,1,BRIDGE_ERR_ARGUMENT},
        {1,0,BRIDGE_LAYOUT_US,BRIDGE_MODE_PASSWORD,0,data,1,1,BRIDGE_ERR_ARGUMENT},
        {1,1,(bridge_layout_t)0,BRIDGE_MODE_PASSWORD,0,data,1,1,BRIDGE_ERR_ARGUMENT},
        {1,1,(bridge_layout_t)99,BRIDGE_MODE_PASSWORD,0,data,1,1,BRIDGE_ERR_ARGUMENT},
        {1,1,BRIDGE_LAYOUT_US,(bridge_mode_t)0,0,data,1,1,BRIDGE_ERR_ARGUMENT},
        {1,1,BRIDGE_LAYOUT_US,(bridge_mode_t)99,0,data,1,1,BRIDGE_ERR_ARGUMENT},
        {1,1,BRIDGE_LAYOUT_US,BRIDGE_MODE_PASSWORD,0,data,1,0,BRIDGE_ERR_ARGUMENT},
        {1,1,BRIDGE_LAYOUT_US,BRIDGE_MODE_PASSWORD,0,data,1,BRIDGE_MAX_TTL_MS+1,BRIDGE_ERR_ARGUMENT},
        {1,1,BRIDGE_LAYOUT_US,BRIDGE_MODE_TEXT,4,data,1,1,BRIDGE_ERR_POLICY},
        {1,1,BRIDGE_LAYOUT_US,BRIDGE_MODE_PASSWORD,BRIDGE_FLAG_ALLOW_LF,data,1,1,BRIDGE_ERR_POLICY},
        {1,1,BRIDGE_LAYOUT_US,BRIDGE_MODE_PASSWORD,BRIDGE_FLAG_ALLOW_TAB,data,1,1,BRIDGE_ERR_POLICY}
    };
    for (size_t i=0; i<sizeof bad/sizeof bad[0]; ++i) {
        bridge_core_init(&core);
        CHECK(bridge_core_stage(&core,bad[i].owner,bad[i].id,bad[i].layout,
              bad[i].mode,bad[i].flags,bad[i].data,bad[i].len,0,bad[i].ttl) == bad[i].status);
        CHECK(core.state == BRIDGE_STATE_REJECTED && payload_wiped(&core));
    }
    bridge_core_init(&core);
    CHECK(bridge_core_stage(&core,1,1,BRIDGE_LAYOUT_US,BRIDGE_MODE_PASSWORD,
          0,data,BRIDGE_MAX_INPUT_BYTES,0,BRIDGE_MAX_TTL_MS) == BRIDGE_OK);
    CHECK(core.stroke_count == BRIDGE_MAX_INPUT_BYTES);
    CHECK(bridge_core_stage(NULL,1,1,BRIDGE_LAYOUT_US,BRIDGE_MODE_PASSWORD,
          0,data,1,0,1) == BRIDGE_ERR_ARGUMENT);
    bridge_core_init(NULL);
}

static void control_policy_matrix(void)
{
    for (unsigned mode=BRIDGE_MODE_PASSWORD; mode<=BRIDGE_MODE_TEXT; ++mode) {
        for (unsigned flags=0; flags<=3; ++flags) {
            for (unsigned cp=0; cp<=127; ++cp) {
                if (cp>=32 && cp!=127) continue;
                for (unsigned layout=BRIDGE_LAYOUT_US; layout<=BRIDGE_LAYOUT_DE; ++layout) {
                    bridge_core_t core;
                    uint8_t input[] = {'x',(uint8_t)cp};
                    int allowed = mode == BRIDGE_MODE_TEXT &&
                        ((cp==10 && (flags & BRIDGE_FLAG_ALLOW_LF)) ||
                         (cp==9 && (flags & BRIDGE_FLAG_ALLOW_TAB)));
                    bridge_core_init(&core);
                    bridge_status_t status=bridge_core_stage(&core,1,1,
                        (bridge_layout_t)layout,(bridge_mode_t)mode,(uint8_t)flags,
                        input,sizeof input,0,100);
                    CHECK(status == (allowed ? BRIDGE_OK : BRIDGE_ERR_POLICY));
                    if (allowed) {
                        CHECK(core.stroke_count == 2);
                        CHECK(core.strokes[1].modifier == 0);
                        CHECK(core.strokes[1].usage == (cp==10 ? 0x28 : 0x2b));
                    } else CHECK(payload_wiped(&core));
                }
            }
        }
    }
}

static void strict_utf8_preflight(void)
{
    static const struct { uint8_t bytes[5]; size_t len; } invalid[] = {
        {{0x80},1},{{0xbf},1},{{0xc0,0xaf},2},{{0xc1,0xbf},2},{{0xc2},1},
        {{0xdf},1},{{0xc2,0x41},2},{{0xe0},1},{{0xe0,0xa0},2},
        {{0xe0,0x80,0xaf},3},{{0xe0,0x9f,0xbf},3},{{0xe1,0x41,0x80},3},
        {{0xe1,0x80,0x41},3},{{0xed,0xa0,0x80},3},{{0xed,0xbf,0xbf},3},
        {{0xf0},1},{{0xf0,0x90},2},{{0xf0,0x90,0x80},3},
        {{0xf0,0x80,0x80,0xaf},4},{{0xf0,0x8f,0xbf,0xbf},4},
        {{0xf4,0x90,0x80,0x80},4},{{0xf5,0x80,0x80,0x80},4},
        {{0xfe},1},{{0xff},1},{{'a',0xe2,0x82},3}
    };
    for (size_t i=0; i<sizeof invalid/sizeof invalid[0]; ++i) {
        bridge_core_t core;
        bridge_core_init(&core);
        CHECK(bridge_core_stage(&core,1,1,BRIDGE_LAYOUT_US,BRIDGE_MODE_TEXT,
              3,invalid[i].bytes,invalid[i].len,0,100) == BRIDGE_ERR_UTF8);
        CHECK(core.state == BRIDGE_STATE_REJECTED && payload_wiped(&core));
    }
    static const struct { uint8_t bytes[4]; size_t len; } unsupported[] = {
        {{0xc2,0x80},2},{{0xdf,0xbf},2},{{0xe0,0xa0,0x80},3},
        {{0xed,0x9f,0xbf},3},{{0xee,0x80,0x80},3},{{0xef,0xbf,0xbf},3},
        {{0xf0,0x90,0x80,0x80},4},{{0xf4,0x8f,0xbf,0xbf},4},
        {{0xf0,0x9f,0x98,0x80},4},{{0xcc,0x88},2}
    };
    for (size_t i=0; i<sizeof unsupported/sizeof unsupported[0]; ++i) {
        bridge_core_t core;
        bridge_core_init(&core);
        CHECK(bridge_core_stage(&core,1,1,BRIDGE_LAYOUT_US,BRIDGE_MODE_PASSWORD,
              0,unsupported[i].bytes,unsupported[i].len,0,100) == BRIDGE_ERR_UNSUPPORTED);
        CHECK(payload_wiped(&core));
    }
}

static void de_ascii_dead_key_profile(void)
{
    static const struct { uint8_t ch,modifier,usage; } punctuation[] = {
        {' ',0,44},{'!',2,30},{'"',2,31},{'#',0,50},{'$',2,33},{'%',2,34},
        {'&',2,35},{'\'',2,50},{'(',2,37},{')',2,38},{'*',2,48},{'+',0,48},
        {',',0,54},{'-',0,56},{'.',0,55},{'/',2,36},{':',2,55},{';',2,54},
        {'<',0,100},{'=',2,39},{'>',2,100},{'?',2,45},{'@',64,20},
        {'[',64,37},{'\\',64,45},{']',64,38},{'^',0,53},{'_',2,56},
        {'`',2,46},{'{',64,36},{'|',64,100},{'}',64,39},{'~',64,48}
    };
    for (unsigned cp=32; cp<=126; ++cp) {
        bridge_core_t core;
        uint8_t input = (uint8_t)cp;
        uint8_t usage=0, modifier=0;
        if (cp>='A' && cp<='Z') { usage=(uint8_t)(cp-'A'+4); modifier=2; }
        if (cp>='a' && cp<='z') usage=(uint8_t)(cp-'a'+4);
        if (cp=='y' || cp=='Y') usage=29;
        if (cp=='z' || cp=='Z') usage=28;
        if (cp>='1' && cp<='9') usage=(uint8_t)(cp-'1'+30);
        if (cp=='0') usage=39;
        for (size_t i=0; i<sizeof punctuation/sizeof punctuation[0]; ++i) {
            if (cp==punctuation[i].ch) {
                usage=punctuation[i].usage;
                modifier=punctuation[i].modifier;
            }
        }
        CHECK(usage != 0);
        bridge_core_init(&core);
        CHECK(bridge_core_stage(&core,1,1,BRIDGE_LAYOUT_DE,BRIDGE_MODE_PASSWORD,
              0,&input,1,0,100) == BRIDGE_OK);
        CHECK(core.strokes[0].modifier == modifier && core.strokes[0].usage == usage);
        int dead = cp=='^' || cp=='`' || cp=='~';
        CHECK(core.stroke_count == (dead ? 2u : 1u));
        if (dead) CHECK(core.strokes[1].modifier == 0 && core.strokes[1].usage == 44);
    }
    uint8_t maximum[BRIDGE_MAX_INPUT_BYTES];
    memset(maximum,'^',sizeof maximum);
    bridge_core_t core;
    bridge_core_init(&core);
    CHECK(bridge_core_stage(&core,1,1,BRIDGE_LAYOUT_DE,BRIDGE_MODE_PASSWORD,
          0,maximum,sizeof maximum,0,100) == BRIDGE_OK);
    CHECK(core.stroke_count == BRIDGE_MAX_STROKES);
    for (size_t i=0; i<core.stroke_count; ++i) {
        CHECK(core.strokes[i].modifier == 0);
        CHECK(core.strokes[i].usage == (i%2 == 0 ? 53 : 44));
    }
}

static void de_unicode_and_layout_isolation(void)
{
    static const uint8_t input[] = {
        0xc3,0xa4,0xc3,0xb6,0xc3,0xbc,0xc3,0x84,0xc3,0x96,0xc3,0x9c,
        0xc3,0x9f,0xe2,0x82,0xac,0xc2,0xb4,'a'
    };
    static const bridge_stroke_t expected[] = {
        {0,52},{0,51},{0,47},{2,52},{2,51},{2,47},{0,45},{64,8},
        {0,46},{0,44},{0,4}
    };
    bridge_core_t core;
    bridge_core_init(&core);
    CHECK(bridge_core_stage(&core,1,1,BRIDGE_LAYOUT_DE,BRIDGE_MODE_PASSWORD,
          0,input,sizeof input,0,100) == BRIDGE_OK);
    CHECK(core.stroke_count == sizeof expected/sizeof expected[0]);
    CHECK(memcmp(core.strokes,expected,sizeof expected) == 0);
    bridge_core_init(&core);
    CHECK(bridge_core_stage(&core,1,1,BRIDGE_LAYOUT_US,BRIDGE_MODE_PASSWORD,
          0,input,sizeof input,0,100) == BRIDGE_ERR_UNSUPPORTED);
    CHECK(payload_wiped(&core));
    static const uint8_t unsupported[] = {'a',0xcc,0x88};
    bridge_core_init(&core);
    CHECK(bridge_core_stage(&core,1,1,BRIDGE_LAYOUT_DE,BRIDGE_MODE_PASSWORD,
          0,unsupported,sizeof unsupported,0,100) == BRIDGE_ERR_UNSUPPORTED);
    CHECK(payload_wiped(&core));
}

static void confirmed_transaction_once(void)
{
    bridge_core_t core;
    bridge_stroke_t stroke = {0xff,0xff};
    uint8_t data[] = "aA!";
    static const bridge_stroke_t expected[] = {{0,4},{2,4},{2,30}};
    bridge_core_init(&core);
    CHECK(bridge_core_stage(&core,7,12,BRIDGE_LAYOUT_US,BRIDGE_MODE_PASSWORD,
          0,data,sizeof data-1,100,1000) == BRIDGE_OK);
    memset(data,'z',sizeof data-1);
    CHECK(bridge_core_confirm(&core,7,12,101) == BRIDGE_OK);
    CHECK(core.state == BRIDGE_STATE_EXECUTING && core.cursor == 0);
    for (size_t i=0; i<sizeof expected/sizeof expected[0]; ++i) {
        CHECK(bridge_core_next(&core,102,&stroke) == BRIDGE_OK);
        CHECK(stroke.modifier == expected[i].modifier && stroke.usage == expected[i].usage);
        CHECK(core.strokes[i].modifier == 0 && core.strokes[i].usage == 0);
    }
    CHECK(bridge_core_next(&core,103,&stroke) == BRIDGE_DONE);
    CHECK(stroke.modifier == 0 && stroke.usage == 0);
    CHECK(core.state == BRIDGE_STATE_COMPLETED && payload_wiped(&core));
    CHECK(bridge_core_confirm(&core,7,12,104) == BRIDGE_ERR_STATE);
    stroke.modifier=0xff; stroke.usage=0xff;
    CHECK(bridge_core_next(&core,104,&stroke) == BRIDGE_ERR_STATE);
    CHECK(stroke.modifier == 0 && stroke.usage == 0);
    CHECK(core.state == BRIDGE_STATE_COMPLETED);
}

static bridge_status_t stage_example(bridge_core_t *core, uint32_t id,
                                     uint32_t now, uint32_t ttl)
{
    static const uint8_t example[] = "az!";
    bridge_core_init(core);
    return bridge_core_stage(core,7,id,BRIDGE_LAYOUT_US,BRIDGE_MODE_PASSWORD,
                             0,example,sizeof example-1,now,ttl);
}
static void confirmation_owner_id_binding(void)
{
    bridge_core_t core;
    bridge_stroke_t stroke;
    CHECK(stage_example(&core,1,0,100) == BRIDGE_OK);
    bridge_core_t before = core;
    CHECK(bridge_core_confirm(&core,8,1,1) == BRIDGE_ERR_OWNER);
    CHECK(memcmp(&core,&before,sizeof core) == 0);
    CHECK(bridge_core_next(&core,1,&stroke) == BRIDGE_ERR_STATE);
    CHECK(stroke.modifier == 0 && stroke.usage == 0);
    CHECK(bridge_core_confirm(&core,7,2,1) == BRIDGE_ERR_ID);
    CHECK(memcmp(&core,&before,sizeof core) == 0);
    CHECK(bridge_core_confirm(&core,7,1,1) == BRIDGE_OK);
    CHECK(bridge_core_confirm(&core,7,1,1) == BRIDGE_ERR_STATE);
}

static void fixed_1024_byte_budget(void)
{
    bridge_core_t core;
    uint8_t input[1025];
    memset(input,'^',sizeof input);
    bridge_core_init(&core);
    CHECK(bridge_core_stage(&core,1,1,BRIDGE_LAYOUT_DE,BRIDGE_MODE_PASSWORD,
          0,input,1024,0,100) == BRIDGE_OK);
    CHECK(BRIDGE_MAX_INPUT_BYTES == 1024 && core.stroke_count == 2048);
    CHECK(BRIDGE_MAX_STROKES == 2048);
    bridge_core_init(&core);
    CHECK(bridge_core_stage(&core,1,1,BRIDGE_LAYOUT_DE,BRIDGE_MODE_PASSWORD,
          0,input,1025,0,100) == BRIDGE_ERR_LIMIT);
    CHECK(payload_wiped(&core));
    for (size_t i=0; i<1024; i+=2) { input[i]=0xc3; input[i+1]=0xa4; }
    CHECK(bridge_core_stage(&core,1,2,BRIDGE_LAYOUT_DE,BRIDGE_MODE_PASSWORD,
          0,input,1024,0,100) == BRIDGE_OK);
    CHECK(core.stroke_count == 512);
}

static void explicit_crlf_policy(void)
{
    static const uint8_t input[] = " a\r\n\tZ\n ";
    static const bridge_stroke_t expected[] = {
        {0,44},{0,4},{0,40},{0,43},{2,29},{0,40},{0,44}
    };
    for (unsigned layout=BRIDGE_LAYOUT_US; layout<=BRIDGE_LAYOUT_DE; ++layout) {
        for (unsigned flags=0; flags<=3; ++flags) {
            bridge_core_t core;
            bridge_core_init(&core);
            CHECK(bridge_core_stage(&core,7,1,(bridge_layout_t)layout,
                  BRIDGE_MODE_TEXT,(uint8_t)flags,input,sizeof input-1,0,100) ==
                  (flags==3 ? BRIDGE_OK : BRIDGE_ERR_POLICY));
            if (flags==3) {
                CHECK(core.stroke_count == sizeof expected/sizeof expected[0]);
                for (size_t i=0; i<core.stroke_count; ++i) {
                    CHECK(core.strokes[i].modifier == expected[i].modifier);
                    CHECK(core.strokes[i].usage ==
                          (i==4 && layout==BRIDGE_LAYOUT_DE ? 28 : expected[i].usage));
                }
            } else CHECK(payload_wiped(&core));
        }
    }
    static const char *bad[] = {"\r", "x\r", "\rx", "\r\r\n"};
    for (size_t i=0; i<sizeof bad/sizeof bad[0]; ++i) {
        bridge_core_t core;
        bridge_core_init(&core);
        CHECK(bridge_core_stage(&core,7,1,BRIDGE_LAYOUT_US,BRIDGE_MODE_TEXT,
              3,(const uint8_t *)bad[i],strlen(bad[i]),0,100) == BRIDGE_ERR_POLICY);
        CHECK(payload_wiped(&core));
    }
}

static void busy_preserves_frozen_job(void)
{
    bridge_core_t core;
    CHECK(stage_example(&core,1,0,100) == BRIDGE_OK);
    for (unsigned executing=0; executing<=1; ++executing) {
        bridge_core_t before = core;
        static const uint8_t replacement[] = "Y";
        CHECK(bridge_core_stage(&core,8,2,BRIDGE_LAYOUT_DE,BRIDGE_MODE_TEXT,
              3,replacement,1,1,100) == BRIDGE_ERR_BUSY);
        CHECK(memcmp(&before,&core,sizeof core) == 0);
        CHECK(bridge_core_stage(&core,7,1,(bridge_layout_t)0,(bridge_mode_t)0,
              255,NULL,SIZE_MAX,1,0) == BRIDGE_ERR_BUSY);
        CHECK(memcmp(&before,&core,sizeof core) == 0);
        if (!executing) CHECK(bridge_core_confirm(&core,7,1,1) == BRIDGE_OK);
    }
}

static void stage_window_15s_wrap(void)
{
    bridge_core_t core;
    static const uint8_t input[] = "x";
    bridge_core_init(&core);
    CHECK(bridge_core_stage(&core,7,1,BRIDGE_LAYOUT_US,BRIDGE_MODE_PASSWORD,
          0,input,1,0,15001) == BRIDGE_ERR_ARGUMENT);
    CHECK(payload_wiped(&core));
    CHECK(BRIDGE_MAX_TTL_MS == 15000);
    static const uint32_t starts[] = {0, 123, UINT32_MAX-20};
    for (size_t i=0; i<sizeof starts/sizeof starts[0]; ++i) {
        uint32_t start = starts[i];
        CHECK(stage_example(&core,1,start,15000) == BRIDGE_OK);
        CHECK(bridge_core_confirm(&core,7,1,start+14999u) == BRIDGE_OK);
        CHECK(stage_example(&core,1,start,15000) == BRIDGE_OK);
        CHECK(bridge_core_confirm(&core,7,1,start+15000u) == BRIDGE_ERR_EXPIRED);
        CHECK(core.state == BRIDGE_STATE_EXPIRED && payload_wiped(&core));
        CHECK(bridge_core_confirm(&core,7,1,start+15001u) == BRIDGE_ERR_STATE);
        CHECK(stage_example(&core,1,start,7) == BRIDGE_OK);
        CHECK(bridge_core_confirm(&core,7,1,start+7u) == BRIDGE_ERR_EXPIRED);
    }
}

static void scheduler_expiry_no_implicit_confirmation(void)
{
    bridge_core_t core;
    bridge_stroke_t stroke = {255,255};
    bridge_core_init(&core);
    CHECK(bridge_core_tick(&core,0) == BRIDGE_OK);
    CHECK(bridge_core_confirm(&core,7,1,0) == BRIDGE_ERR_STATE);
    CHECK(bridge_core_next(&core,0,&stroke) == BRIDGE_ERR_STATE);
    CHECK(stroke.modifier == 0 && stroke.usage == 0);
    uint32_t start = UINT32_MAX-5;
    CHECK(stage_example(&core,1,start,10) == BRIDGE_OK);
    CHECK(bridge_core_tick(&core,start+9u) == BRIDGE_OK);
    CHECK(bridge_core_next(&core,start+9u,&stroke) == BRIDGE_ERR_STATE);
    CHECK(core.state == BRIDGE_STATE_STAGED && core.cursor == 0);
    CHECK(bridge_core_tick(&core,start+10u) == BRIDGE_ERR_EXPIRED);
    CHECK(core.state == BRIDGE_STATE_EXPIRED && payload_wiped(&core));
    CHECK(bridge_core_tick(&core,start+11u) == BRIDGE_OK);
    CHECK(stage_example(&core,1,0,10) == BRIDGE_OK);
    CHECK(bridge_core_next(&core,10,&stroke) == BRIDGE_ERR_EXPIRED);
    CHECK(stroke.modifier == 0 && stroke.usage == 0 && payload_wiped(&core));
    CHECK(stage_example(&core,1,0,10) == BRIDGE_OK);
    CHECK(bridge_core_confirm(&core,7,1,9) == BRIDGE_OK);
    CHECK(bridge_core_tick(&core,10) == BRIDGE_OK);
    CHECK(core.state == BRIDGE_STATE_EXECUTING);
    CHECK(bridge_core_next(&core,10,&stroke) == BRIDGE_OK);
}

static void cancel_owner_binding_wipes(void)
{
    bridge_core_t core;
    bridge_stroke_t stroke;
    for (unsigned executing=0; executing<=1; ++executing) {
        CHECK(stage_example(&core,1,0,100) == BRIDGE_OK);
        if (executing) {
            CHECK(bridge_core_confirm(&core,7,1,1) == BRIDGE_OK);
            CHECK(bridge_core_next(&core,2,&stroke) == BRIDGE_OK);
        }
        bridge_core_t before = core;
        CHECK(bridge_core_cancel(&core,8,1) == BRIDGE_ERR_OWNER);
        CHECK(memcmp(&before,&core,sizeof core) == 0);
        CHECK(bridge_core_cancel(&core,7,2) == BRIDGE_ERR_ID);
        CHECK(memcmp(&before,&core,sizeof core) == 0);
        CHECK(bridge_core_cancel(&core,7,1) == BRIDGE_OK);
        CHECK(core.state == BRIDGE_STATE_CANCELLED && payload_wiped(&core));
        CHECK(bridge_core_cancel(&core,7,1) == BRIDGE_ERR_STATE);
        CHECK(bridge_core_confirm(&core,7,1,3) == BRIDGE_ERR_STATE);
        CHECK(bridge_core_next(&core,3,&stroke) == BRIDGE_ERR_STATE);
        CHECK(stroke.modifier == 0 && stroke.usage == 0);
    }
}

static void disconnect_abort_wipes(void)
{
    for (unsigned progress=0; progress<=4; ++progress) {
        bridge_core_t core;
        bridge_stroke_t stroke = {255,255};
        CHECK(stage_example(&core,1,0,100) == BRIDGE_OK);
        if (progress) {
            CHECK(bridge_core_confirm(&core,7,1,1) == BRIDGE_OK);
            for (unsigned i=1; i<progress; ++i)
                CHECK(bridge_core_next(&core,2,&stroke) == BRIDGE_OK);
        }
        bridge_core_abort(&core);
        CHECK(core.state == BRIDGE_STATE_CANCELLED && payload_wiped(&core));
        bridge_core_abort(&core);
        CHECK(core.state == BRIDGE_STATE_CANCELLED && payload_wiped(&core));
        CHECK(bridge_core_confirm(&core,7,1,3) == BRIDGE_ERR_STATE);
        CHECK(bridge_core_next(&core,3,&stroke) == BRIDGE_ERR_STATE);
        CHECK(stroke.modifier == 0 && stroke.usage == 0);
    }
}

static void replay_ledger_not_just_last_id(void)
{
    bridge_core_t core;
    bridge_stroke_t stroke;
    static const uint8_t input[] = "a";
    /* Deliberately unordered IDs: these are opaque request tokens, not counters. */
    static const uint32_t ids[] = {93, 5, UINT32_MAX, 1, 27};
    bridge_core_init(&core);
    for (size_t i=0; i<sizeof ids/sizeof ids[0]; ++i) {
        CHECK(bridge_core_stage(&core,7,ids[i],BRIDGE_LAYOUT_US,BRIDGE_MODE_PASSWORD,
              0,input,1,0,100) == BRIDGE_OK);
        if (i==0) {
            CHECK(bridge_core_confirm(&core,7,ids[i],0) == BRIDGE_OK);
            CHECK(bridge_core_next(&core,0,&stroke) == BRIDGE_OK);
            CHECK(bridge_core_next(&core,0,&stroke) == BRIDGE_DONE);
        } else if (i==1) CHECK(bridge_core_cancel(&core,7,ids[i]) == BRIDGE_OK);
        else if (i==2) CHECK(bridge_core_tick(&core,100) == BRIDGE_ERR_EXPIRED);
        else bridge_core_abort(&core);
    }
    for (size_t i=0; i<sizeof ids/sizeof ids[0]; ++i) {
        CHECK(bridge_core_stage(&core,7,ids[i],BRIDGE_LAYOUT_US,BRIDGE_MODE_PASSWORD,
              0,input,1,0,100) == BRIDGE_ERR_REPLAY);
        CHECK(payload_wiped(&core));
        CHECK(bridge_core_confirm(&core,7,ids[i],0) == BRIDGE_ERR_STATE);
        CHECK(bridge_core_next(&core,0,&stroke) == BRIDGE_ERR_STATE);
        CHECK(stroke.modifier == 0 && stroke.usage == 0);
    }
    /* A different authenticated session can choose the same request token. */
    CHECK(bridge_core_stage(&core,8,ids[0],BRIDGE_LAYOUT_US,BRIDGE_MODE_PASSWORD,
          0,input,1,0,100) == BRIDGE_OK);
    bridge_core_abort(&core);
    CHECK(bridge_core_stage(&core,7,ids[0],BRIDGE_LAYOUT_US,BRIDGE_MODE_PASSWORD,
          0,input,1,0,100) == BRIDGE_ERR_REPLAY);
}

static void replay_ledger_exhaustion_fails_closed(void)
{
    bridge_core_t core;
    static const uint8_t input[] = "x";
    bridge_core_init(&core);
    for (uint32_t id=1; id<=64; ++id) {
        CHECK(bridge_core_stage(&core,7,id,BRIDGE_LAYOUT_US,BRIDGE_MODE_PASSWORD,
              0,input,1,0,100) == BRIDGE_OK);
        bridge_core_abort(&core);
    }
    CHECK(bridge_core_stage(&core,7,65,BRIDGE_LAYOUT_US,BRIDGE_MODE_PASSWORD,
          0,input,1,0,100) == BRIDGE_ERR_LIMIT);
    CHECK(payload_wiped(&core));
    for (uint32_t id=1; id<=64; ++id) {
        CHECK(bridge_core_stage(&core,7,id,BRIDGE_LAYOUT_US,BRIDGE_MODE_PASSWORD,
              0,input,1,0,100) == BRIDGE_ERR_REPLAY);
        CHECK(payload_wiped(&core));
    }
    CHECK(bridge_core_stage(&core,8,1,BRIDGE_LAYOUT_US,BRIDGE_MODE_PASSWORD,
          0,input,1,0,100) == BRIDGE_ERR_LIMIT);
}

static void null_arguments_do_not_consume(void)
{
    bridge_core_t core;
    bridge_stroke_t stroke = {255,255};
    CHECK(stage_example(&core,1,0,100) == BRIDGE_OK);
    CHECK(bridge_core_confirm(&core,7,1,0) == BRIDGE_OK);
    bridge_core_t before = core;
    CHECK(bridge_core_next(&core,0,NULL) == BRIDGE_ERR_ARGUMENT);
    CHECK(memcmp(&before,&core,sizeof core) == 0);
    CHECK(bridge_core_confirm(NULL,7,1,0) == BRIDGE_ERR_ARGUMENT);
    CHECK(bridge_core_cancel(NULL,7,1) == BRIDGE_ERR_ARGUMENT);
    CHECK(bridge_core_tick(NULL,0) == BRIDGE_ERR_ARGUMENT);
    CHECK(bridge_core_next(NULL,0,&stroke) == BRIDGE_ERR_ARGUMENT);
    CHECK(stroke.modifier == 0 && stroke.usage == 0);
    CHECK(bridge_core_next(NULL,0,NULL) == BRIDGE_ERR_ARGUMENT);
    bridge_core_abort(NULL);
    bridge_core_init(NULL);
    CHECK(bridge_core_next(&core,0,&stroke) == BRIDGE_OK);
    CHECK(stroke.modifier == 0 && stroke.usage == 4);
}

struct test_case { const char *name; void (*run)(void); };
static const struct test_case cases[] = {
    {"null_arguments_do_not_consume", null_arguments_do_not_consume},
    {"replay_ledger_exhaustion_fails_closed", replay_ledger_exhaustion_fails_closed},
    {"replay_ledger_not_just_last_id", replay_ledger_not_just_last_id},
    {"disconnect_abort_wipes", disconnect_abort_wipes},
    {"cancel_owner_binding_wipes", cancel_owner_binding_wipes},
    {"scheduler_expiry_no_implicit_confirmation", scheduler_expiry_no_implicit_confirmation},
    {"stage_window_15s_wrap", stage_window_15s_wrap},
    {"busy_preserves_frozen_job", busy_preserves_frozen_job},
    {"explicit_crlf_policy", explicit_crlf_policy},
    {"fixed_1024_byte_budget", fixed_1024_byte_budget},
    {"confirmation_owner_id_binding", confirmation_owner_id_binding},
    {"confirmed_transaction_once", confirmed_transaction_once},
    {"de_unicode_and_layout_isolation", de_unicode_and_layout_isolation},
    {"de_ascii_dead_key_profile", de_ascii_dead_key_profile},
    {"strict_utf8_preflight", strict_utf8_preflight},
    {"control_policy_matrix", control_policy_matrix},
    {"bounded_request_validation", bounded_request_validation},
    {"rejected_preflight_wipes", rejected_preflight_wipes},
    {"us_printable_ascii", us_printable_ascii},
    {"stage_us_letter", stage_us_letter},
};
int main(int argc, char **argv)
{
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        if (argc > 1 && strcmp(argv[1], cases[i].name) != 0) continue;
        unsigned before = failures;
        ++tests_run;
        cases[i].run();
        printf("%s %s\n", failures == before ? "PASS" : "FAIL", cases[i].name);
    }
    printf("%u tests, %u failures\n", tests_run, failures);
    return failures != 0 || tests_run == 0;
}
