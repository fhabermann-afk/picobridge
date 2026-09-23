#ifndef RADIO_HTTP_PARSER_H
#define RADIO_HTTP_PARSER_H
#include <stddef.h>
#include <stdint.h>
#define RADIO_HTTP_MAX 1024u
enum radio_http_result { HTTP_MORE=0, HTTP_ROOT=1, HTTP_HEALTH=2,
    HTTP_BAD=400, HTTP_NOT_FOUND=404, HTTP_METHOD=405, HTTP_LARGE=431 };
enum radio_http_result radio_http_parse(const uint8_t *data,size_t length);
#endif
