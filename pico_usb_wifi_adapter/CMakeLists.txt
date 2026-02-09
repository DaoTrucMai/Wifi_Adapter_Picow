cmake_minimum_required(VERSION 3.13)

include(pico_sdk_import.cmake)

project(pico_usb_wifi_adapter C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

set(PICO_CYW43_DRIVER_PATH ${CMAKE_CURRENT_LIST_DIR}/third_party/cyw43-driver)

pico_sdk_init()

add_executable(pico_usb_wifi_adapter
    src/main.c
    src/usb/usb_device.c
    src/usb/pwusb_transport.c
    src/usb/pwusb_handlers.c
    src/wifi/wifi_mgr.c
    src/util/ringbuf.c
    src/util/msg_queue.c
)

target_include_directories(pico_usb_wifi_adapter PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/include
    ${CMAKE_CURRENT_LIST_DIR}
)

# We keep USB stdio off; we use vendor bulk for protocol.
pico_enable_stdio_usb(pico_usb_wifi_adapter 0)
pico_enable_stdio_uart(pico_usb_wifi_adapter 1)

# Wi-Fi stack (polling) without lwIP; we pass raw Ethernet frames to the host.
target_link_libraries(pico_usb_wifi_adapter
    pico_stdlib
    pico_cyw43_arch_poll
    tinyusb_device
    tinyusb_board
)

# TinyUSB config header
target_compile_definitions(pico_usb_wifi_adapter PRIVATE
    CFG_TUSB_CONFIG_FILE=\"tusb_config.h\"
    CYW43_LWIP=0
)

pico_add_extra_outputs(pico_usb_wifi_adapter)
