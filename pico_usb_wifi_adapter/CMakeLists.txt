cmake_minimum_required(VERSION 3.13)

include(pico_sdk_import.cmake)

set(PICO_BOARD pico_w CACHE STRING "Board type for pico_usb_wifi_adapter" FORCE)

project(pico_usb_wifi_adapter C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# Optional firmware debug logs (all OFF by default).
option(PWUSB_USB_DEBUG "Enable verbose USB transport logs" OFF)
option(PWUSB_WIFI_DEBUG "Enable verbose Wi-Fi manager logs" OFF)
option(PWUSB_DHCP_DEBUG "Enable DHCP packet tracing logs" OFF)
option(PWUSB_PERF_DEBUG "Enable 1 Hz perf summary logs" OFF)

set(PICO_CYW43_DRIVER_PATH ${CMAKE_CURRENT_LIST_DIR}/third_party/cyw43-driver)

pico_sdk_init()

add_executable(pico_usb_wifi_adapter
    src/main.c
    src/usb/usb_device.c
    src/usb/pwusb_transport.c
    src/usb/pwusb_handlers.c
    ${CMAKE_CURRENT_LIST_DIR}/../usb_library_rp2040/src/usb.c
    src/wifi/wifi_mgr.c
    src/pwusb_perf.c
    src/util/ringbuf.c
    src/util/msg_queue.c
)

target_include_directories(pico_usb_wifi_adapter PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/include
    ${CMAKE_CURRENT_LIST_DIR}
    ${PICO_CYW43_DRIVER_PATH}/src
    ${PICO_SDK_PATH}/src/rp2_common/pico_cyw43_driver/include
    ${PICO_SDK_PATH}/src/rp2_common/pico_cyw43_arch/include
    ${PICO_SDK_PATH}/src/rp2_common/pico_async_context/include
    ${CMAKE_CURRENT_LIST_DIR}/../usb_library_rp2040/src
)

# We keep USB stdio off; we use vendor bulk for protocol.
pico_enable_stdio_usb(pico_usb_wifi_adapter 0)
pico_enable_stdio_uart(pico_usb_wifi_adapter 1)

# Wi-Fi stack (polling) without lwIP; we pass raw Ethernet frames to the host.
target_link_libraries(pico_usb_wifi_adapter
    pico_stdlib
    pico_cyw43_arch_poll
    hardware_irq
    hardware_resets
)

target_compile_definitions(pico_usb_wifi_adapter PRIVATE
    CYW43_LWIP=0
    PICO_CYW43_ARCH_POLL=1
)

if (PWUSB_USB_DEBUG)
    target_compile_definitions(pico_usb_wifi_adapter PRIVATE PWUSB_USB_DEBUG=1)
endif()
if (PWUSB_WIFI_DEBUG)
    target_compile_definitions(pico_usb_wifi_adapter PRIVATE PWUSB_WIFI_DEBUG=1)
endif()
if (PWUSB_DHCP_DEBUG)
    target_compile_definitions(pico_usb_wifi_adapter PRIVATE PWUSB_DHCP_DEBUG=1)
endif()
if (PWUSB_PERF_DEBUG)
    target_compile_definitions(pico_usb_wifi_adapter PRIVATE PWUSB_PERF_DEBUG=1)
endif()

pico_add_extra_outputs(pico_usb_wifi_adapter)
