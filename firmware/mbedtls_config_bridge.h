/* User config for bridge firmware — supplements the default mbedtls_config.h.
 * Only overrides/adds defines that differ from the Pico SDK defaults.
 */
#include "mbedtls_config.h"

/* Use pico_rand for entropy (mbedtls_hardware_poll provided by pico_mbedtls.c) */
#define MBEDTLS_NO_PLATFORM_ENTROPY

/* Provide our own mbedtls_ms_time (avoids #error in platform_util.c) */
#define MBEDTLS_PLATFORM_MS_TIME_ALT

/* No portable timing module (only works on Unix/Windows) */
#undef MBEDTLS_TIMING_C

/* No socket support (embedded, no TCP/IP stack) */
#undef MBEDTLS_NET_C
