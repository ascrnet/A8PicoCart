/* SPDX-License-Identifier: MIT */
#ifndef A8_TYPE63_IMAGE_H
#define A8_TYPE63_IMAGE_H
#include "type42_image.h"

#define TYPE63_ROM_BYTES (4u * 1024u * 1024u)
#define TYPE63_FILE_PAGES (TYPE63_ROM_BYTES / 512u + 1u)
#define TYPE63_HALF_PAGES 17u
#define TYPE63_BANK_PAGES (2u * TYPE63_HALF_PAGES)
#define TYPE63_MAP_PAGES (256u * TYPE63_BANK_PAGES)
#define TYPE63_TABLE_BYTES (TYPE63_MAP_PAGES * sizeof(const uint8_t *))
#define TYPE63_CACHE_PAGES ((128u * 1024u - TYPE63_TABLE_BYTES) / 512u)
#define TYPE63_INITIAL_BANK 254u
#define TYPE63_HEAD_CACHE_PAGES 129u
#define TYPE63_INITIAL_CACHE_PAGES 33u
#define TYPE63_USED_CACHE_PAGES (TYPE63_HEAD_CACHE_PAGES + TYPE63_INITIAL_CACHE_PAGES)
#define TYPE63_CACHED_BANK_FLAG ((uintptr_t)1u)
#define TYPE63_BASE_SEAM_COUNT 3u
#define TYPE63_SEAM_COUNT 5u
#define TYPE63_SEAM_SLOT (TYPE42_FILE_PAGES - TYPE63_SEAM_COUNT)
#define TYPE63_HINT_SLOT (TYPE63_SEAM_SLOT - 1u)
#define TYPE63_CACHE_HINT_ROM_OFFSET (255u * 16384u)
#define TYPE63_CACHE_HINT_BYTES 20u
#define TYPE63_CACHE_HINT_VERSION 1u
#define TYPE63_CACHE_HINT_MAGIC "A8C63HNT"
/* Metadata occupies only the existing inactive bank-table tail. No hint keeps
 * the original cache allocation and placement. An admitted hint requests one
 * additional complete bank and allows shared immutable 00/FF sector pages. */
static inline __attribute__((always_inline)) unsigned type63_extra_cached_bank(void) {
    return (unsigned)(uintptr_t)type42_pages[TYPE63_HINT_SLOT];
}
static inline __attribute__((always_inline)) bool type63_cached_bank(unsigned bank) {
    if (type42_mapper_type == 61u) return bank < 4u;
    return bank < 4u || bank == TYPE63_INITIAL_BANK ||
        (type63_extra_cached_bank() && bank == type63_extra_cached_bank());
}
static inline __attribute__((always_inline)) unsigned type63_seam_count(void) {
    if (type42_mapper_type == 61u) return 1u;
    return type63_extra_cached_bank() ? TYPE63_SEAM_COUNT : TYPE63_BASE_SEAM_COUNT;
}
static inline __attribute__((always_inline)) unsigned type63_seam_page(unsigned seam) {
    if (!seam) return TYPE63_HEAD_CACHE_PAGES - 1u;
    if (seam < TYPE63_BASE_SEAM_COUNT)
        return TYPE63_INITIAL_BANK * 32u + (seam == 2u ? 32u : 0u);
    return type63_extra_cached_bank() * 32u + (seam == 4u ? 32u : 0u);
}
/* The declared linked deadline model passes with at most this additional
 * uncached-load latency over an identical SRAM load. This checks that one
 * component on the device; it is not an electrical bus qualification. */
#define TYPE63_FLASH_MAX_EXTRA_CYCLES 52u
#define TYPE63_PROBE_COPY_BYTES 1024u
#define TYPE63_SSI_MAX_EXTRA_CYCLES 2u
/* A mode refusal packs the SSI register offset above its low-byte status.
 * type63_flash_extra_cycles then carries that register's raw readback. */
#define TYPE63_PREFLIGHT_STATUS_MASK 0xffu
#define TYPE63_PREFLIGHT_REGISTER_SHIFT 8u
enum {
    TYPE63_PREFLIGHT_OK,
    TYPE63_PREFLIGHT_INTEGRITY,
    TYPE63_PREFLIGHT_TIMER_BUSY,
    TYPE63_PREFLIGHT_TOO_SLOW,
    TYPE63_PREFLIGHT_SSI_MODE,
    TYPE63_PREFLIGHT_SSI_TOO_SLOW
};
/* Raw file-sector pointers occupy the start of cart_ram during admission.
 * Preparation expands them backwards into two 17-pointer half-window maps
 * per bank. Cached banks use biased SRAM pointers; other banks use pre-encoded
 * SSI address/mode commands. A bank-map pointer's low bit marks cached banks.
 * The inactive bank-table tail holds the probe/loop; its last three slots
 * retain physical seam originals and an optional extra-bank ID. The fixed
 * 128 KiB allocation has capacity for 188 sectors. Legacy images retain the
 * original 162 cached sectors; hinted images reject before exceeding 188. */
extern const uint8_t **type63_pages;
extern uint32_t type63_payload_hash;
extern uint32_t type63_flash_extra_cycles;
extern uint32_t type63_preflight_result;
extern bool type63_admission_checked;
bool type63_load_image(FIL *file, uint8_t *cache_128k, char error[40]);
/* MegaMax 2 MiB shares the checked immutable reader, with address banking. */
bool type61_load_image(FIL *file, uint8_t *cache_128k, char error[40]);
void type61_install_bus(void);
void type61_bus_loop(const uint8_t **pages, const uint8_t **bases) __attribute__((noreturn));
/* Requires the raw admission map, before type63_prepare_bus. */
bool type63_verify_fast_flash(void);
/* Install the steady SRAM reader during preparation, before launch ACK. */
void type63_install_bus(void);
void type63_prepare_bus(void);
void type63_bus_loop(const uint8_t **pages, const uint8_t **bases) __attribute__((noreturn));
#endif
