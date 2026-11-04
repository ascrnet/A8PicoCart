# == DO NOT EDIT THE FOLLOWING LINES for the Raspberry Pi Pico VS Code Extension to work ==
if(WIN32)
    set(USERHOME $ENV{USERPROFILE})
else()
    set(USERHOME $ENV{HOME})
endif()
set(sdkVersion 2.3.0)
set(toolchainVersion 11_3_Rel1)
set(picotoolVersion 2.3.0)
set(picoVscode ${USERHOME}/.pico-sdk/cmake/pico-vscode.cmake)
if (EXISTS ${picoVscode})
    include(${picoVscode})
endif()
# ====================================================================================
cmake_minimum_required(VERSION 3.13)

# initialize the SDK based on PICO_SDK_PATH
# note: this must happen before project()
set(PICO_BOARD_HEADER_DIRS ${CMAKE_CURRENT_LIST_DIR})
set(PICO_BOARD myboard)
include(pico_sdk_import.cmake)

project(a8_pico_cart)

# initialize the Raspberry Pi Pico SDK
pico_sdk_init()

add_executable(a8_pico_cart)

# 16megs of flash on purple pico clones
target_compile_definitions(a8_pico_cart PRIVATE
    PICO_FLASH_SIZE_BYTES=16777216
)

# Large ROMs use flash directly at an experimental Winbond-only speed.
# Keep the existing SRAM-only firmware as the default for other flash chips.
option(A8_ENABLE_TYPE42 "Enable 1/2/4 MiB flash cartridges (Winbond flash)" OFF)
set(A8_TYPE42_FLASH_DIVIDER 2 CACHE STRING "Type42 flash divider (2 or 4)")
if(A8_ENABLE_TYPE42)
    # The copied SRAM probe has a fixed 1024-byte bound, qualified with 11.3.
    # GCC 13.2 exceeds it. Refuse unqualified compilers before creating a UF2.
    if(NOT CMAKE_C_COMPILER_VERSION MATCHES "^11\\.3\\.")
        message(FATAL_ERROR "Winbond cartridge mode requires Arm GNU 11.3.Rel1; other compiler versions are not qualified for the fixed SRAM probe")
    endif()
    target_compile_definitions(a8_pico_cart PRIVATE
        A8_ENABLE_TYPE42=1 PICO_STACK_SIZE=0x1000
        A8_TYPE42_FLASH_DIVIDER=${A8_TYPE42_FLASH_DIVIDER})
    target_sources(a8_pico_cart PRIVATE
        type42_image.c type42_bus.c type42_loop.S type63_image.c type63_loop.S type61_loop.S)
endif()

#pico_set_linker_script(a8_pico_cart ${CMAKE_CURRENT_SOURCE_DIR}/memmap_custom.ld)

target_sources(a8_pico_cart PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/main.c
    ${CMAKE_CURRENT_LIST_DIR}/atari_cart.c
    ${CMAKE_CURRENT_LIST_DIR}/msc_disk.c
    ${CMAKE_CURRENT_LIST_DIR}/usb_descriptors.c
    ${CMAKE_CURRENT_LIST_DIR}/fatfs_disk.c
    ${CMAKE_CURRENT_LIST_DIR}/flash_fs.c
    ${CMAKE_CURRENT_LIST_DIR}/fatfs/ff.c
    ${CMAKE_CURRENT_LIST_DIR}/fatfs/ffunicode.c
    ${CMAKE_CURRENT_LIST_DIR}/fatfs/diskio.c
) 

target_include_directories(a8_pico_cart PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/fatfs
)

# In addition to pico_stdlib required for common PicoSDK functionality, add dependency on tinyusb_device
# for TinyUSB device support
target_link_libraries(a8_pico_cart PUBLIC pico_stdlib hardware_flash tinyusb_device)

# create map/bin/hex/uf2 file in addition to ELF.
pico_add_extra_outputs(a8_pico_cart)
