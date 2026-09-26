cmake_minimum_required(VERSION 3.13)
set(PICO_BOARD pico2_w CACHE STRING "Target board")
set(PICO_SDK_PATH "${CMAKE_CURRENT_LIST_DIR}/vendor/pico-sdk" CACHE PATH "Pinned SDK")
set(picotool_DIR "${CMAKE_CURRENT_LIST_DIR}/vendor/tools/lib/cmake/picotool" CACHE PATH "Pinned host picotool")
include(${PICO_SDK_PATH}/external/pico_sdk_import.cmake)
project(pico_bridge C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
pico_sdk_init()
add_executable(pico_bridge_idle firmware/idle_main.c firmware/usb_descriptors.c)
target_include_directories(pico_bridge_idle PRIVATE firmware)
target_compile_options(pico_bridge_idle PRIVATE -Wall -Wextra)
target_link_libraries(pico_bridge_idle pico_stdlib pico_unique_id pico_cyw43_arch_none tinyusb_device hardware_watchdog)
pico_enable_stdio_usb(pico_bridge_idle 0)
pico_enable_stdio_uart(pico_bridge_idle 0)
pico_set_program_name(pico_bridge_idle "PicoBridge idle USB test")
pico_set_program_version(pico_bridge_idle "0.1.0-test")
pico_add_extra_outputs(pico_bridge_idle)

add_executable(pico_bridge firmware/bridge_main.c firmware/usb_descriptors.c
    firmware/core/bridge_core.c firmware/radio/radio_config.c
    firmware/radio/radio_provision_flash.c
    firmware/radio/http_parser.c firmware/radio/entropy_fill.c
    firmware/radio/dhcp_wire.c firmware/noise_ik.c firmware/controller_store.c
    firmware/controller_store_flash.c)
target_include_directories(pico_bridge PRIVATE firmware firmware/core firmware/radio
    ${PICO_SDK_PATH}/lib/mbedtls/include ${PICO_SDK_PATH}/lib/mbedtls/include/mbedtls)
target_compile_definitions(pico_bridge PRIVATE MBEDTLS_USER_CONFIG_FILE="mbedtls_config_bridge.h")
target_compile_options(pico_bridge PRIVATE -Wall -Wextra)
target_link_libraries(pico_bridge pico_stdlib pico_unique_id pico_rand pico_sha256
    pico_mbedtls pico_mbedtls_headers pico_btstack_ble pico_btstack_cyw43 pico_btstack_flash_bank pico_btstack_run_loop_async_context
    pico_cyw43_arch_none tinyusb_device hardware_watchdog pico_flash)
pico_enable_stdio_usb(pico_bridge 0)
pico_enable_stdio_uart(pico_bridge 0)
pico_set_program_name(pico_bridge "PicoBridge")
pico_set_program_version(pico_bridge "0.2.0")
pico_add_extra_outputs(pico_bridge)
