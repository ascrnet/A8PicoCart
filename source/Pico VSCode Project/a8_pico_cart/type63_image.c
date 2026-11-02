/* SPDX-License-Identifier: MIT */
#include "type63_image.h"
#include "flash_fs.h"
#include <stdio.h>
#include <string.h>

const uint8_t **type63_pages;
uint32_t type63_payload_hash;
uint32_t type63_flash_extra_cycles;
uint32_t type63_preflight_result;
bool type63_admission_checked;
_Static_assert(TYPE63_TABLE_BYTES + TYPE63_CACHE_PAGES * 512u == 128u * 1024u,
               "Type63 must retain the fixed cartridge RAM budget");
/* A bank uses one representation throughout: biased SRAM pointers, or SSI
 * address commands. Hints may use the remaining capacity without changing
 * that steady-reader contract or the fixed arena size. */
_Static_assert(TYPE63_USED_CACHE_PAGES <= TYPE63_CACHE_PAGES,
               "Type63 whole-bank cache exceeds the fixed cartridge RAM");

static uint32_t be32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static uint32_t hint_crc32(const uint8_t *p, unsigned count) {
    uint32_t crc = 0xffffffffu;
    while (count--) {
        crc ^= *p++;
        for (unsigned bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}

static bool load_large_image(FIL *file, uint8_t *cache_128k, char error[40], unsigned cart_type) {
    const unsigned rom_bytes = cart_type == 61u ? 2u * 1024u * 1024u : TYPE63_ROM_BYTES;
    const unsigned file_pages = rom_bytes / 512u + 1u;
    uint8_t sector[512];
    uint32_t checksum = 0, expected = 0, hash = 2166136261u;
    unsigned cached_pages = 0;
    const uint8_t *uniform_zero = NULL, *uniform_ff = NULL;
    type42_mapper_type = 0;
    type63_pages = NULL;
    type63_payload_hash = type63_flash_extra_cycles = 0;
    type63_preflight_result = TYPE63_PREFLIGHT_OK;
    type63_admission_checked = false;
    memset(type42_pages, 0, sizeof(type42_pages));
    memset(type42_bank_base, 0, sizeof(type42_bank_base));
    if (f_size(file) != rom_bytes + 16u) {
        strcpy(error, cart_type == 61u ? "Type61 needs exactly 2MB+16 bytes" : "Type63 needs exactly 4MB+16 bytes");
        return false;
    }
    type63_pages = (const uint8_t **)cache_128k;
    memset(cache_128k, 0, TYPE63_TABLE_BYTES);
    /* Bank FF is disabled by the mapper. This optional, checksummed record
     * changes preparation only; ordinary CARs retain the exact old policy. */
    if (cart_type == 63u) {
    if (f_lseek(file, TYPE42_HEADER_BYTES + TYPE63_CACHE_HINT_ROM_OFFSET) != FR_OK)
        goto read_error;
    {
        UINT got;
        if (f_read(file, sector, TYPE63_CACHE_HINT_BYTES, &got) != FR_OK ||
            got != TYPE63_CACHE_HINT_BYTES) goto read_error;
        if (!memcmp(sector, TYPE63_CACHE_HINT_MAGIC, 8)) {
            uint32_t expected_hint = (uint32_t)sector[16] |
                (uint32_t)sector[17] << 8 | (uint32_t)sector[18] << 16 |
                (uint32_t)sector[19] << 24;
            unsigned extra = sector[11];
            if (sector[8] != TYPE63_CACHE_HINT_VERSION ||
                sector[9] != TYPE63_CACHE_HINT_BYTES || sector[10] != 1u ||
                extra < 4u || extra >= TYPE63_INITIAL_BANK ||
                sector[12] || sector[13] || sector[14] || sector[15] ||
                hint_crc32(sector, 16) != expected_hint) {
                strcpy(error, "Type63 cache hint invalid");
                goto failed;
            }
            type42_pages[TYPE63_HINT_SLOT] = (const uint8_t *)(uintptr_t)extra;
        }
    }
    }
    if (f_lseek(file, 0) != FR_OK) goto read_error;
    type42_mapper_type = cart_type;
    for (unsigned page = 0; page < file_pages; ++page) {
        UINT got;
        unsigned count = page == file_pages - 1 ? 16 : 512;
        if (f_read(file, sector, 1, &got) != FR_OK || got != 1) goto read_error;
        const uint8_t *physical = flash_fs_sector_pointer(file->sect);
        if (!physical) goto read_error;
        /* Adjacent uncached banks share one sector with these cached banks.
         * Preserve original flash locations before replacing the raw map. */
        for (unsigned seam = 0; seam < type63_seam_count(); ++seam)
            if (page == type63_seam_page(seam))
                type42_pages[TYPE63_SEAM_SLOT + seam] = physical;
        if (f_read(file, sector + 1, count - 1, &got) != FR_OK || got != count - 1)
            goto read_error;
        if (!page) {
            if (memcmp(sector, "CART", 4) || be32(sector + 4) != cart_type) {
                strcpy(error, cart_type == 61u ? "Invalid Type61 CAR header" : "Invalid Type63 CAR header");
                goto failed;
            }
            expected = be32(sector + 8);
        }
        for (unsigned i = page ? 0 : 16; i < count; ++i) {
            checksum += sector[i];
            hash = (hash ^ sector[i]) * 16777619u;
        }
        /* Keep complete initial bank FE and the first program banks in SRAM.
         * Bank FF is inaccessible, but remains covered by CAR integrity. */
        const unsigned initial_page = TYPE63_INITIAL_BANK * 32u;
        const unsigned extra_page = type63_extra_cached_bank() * 32u;
        if (page < TYPE63_HEAD_CACHE_PAGES ||
            (page >= initial_page && page <= initial_page + 32u) ||
            (type63_extra_cached_bank() && page >= extra_page && page <= extra_page + 32u)) {
            const uint8_t *target = NULL;
            unsigned uniform = 2u;
            if (type63_extra_cached_bank() && count == 512u &&
                (sector[0] == 0 || sector[0] == 0xff)) {
                unsigned i = 1;
                while (i < count && sector[i] == sector[0]) ++i;
                if (i == count) {
                    uniform = sector[0] == 0 ? 0u : 1u;
                    target = uniform ? uniform_ff : uniform_zero;
                }
            }
            if (!target) {
                if (cached_pages >= TYPE63_CACHE_PAGES) {
                    strcpy(error, "Type63 cache hint exceeds SRAM");
                    goto failed;
                }
                uint8_t *copy = cache_128k + TYPE63_TABLE_BYTES + cached_pages++ * 512u;
                memcpy(copy, sector, count);
                if (count < 512) memset(copy + count, 0xff, 512 - count);
                target = copy;
                if (uniform == 0u) uniform_zero = target;
                else if (uniform == 1u) uniform_ff = target;
            }
            type63_pages[page] = target;
        } else type63_pages[page] = physical;
    }
    if (checksum != expected) {
        strcpy(error, cart_type == 61u ? "Type61 CAR checksum mismatch" : "Type63 CAR checksum mismatch");
        goto failed;
    }
    type42_payload_checksum = checksum;
    type63_payload_hash = hash;
    type42_file_pages = file_pages;
    type42_bank_count = rom_bytes / 16384u;
    type42_initial_bank = cart_type == 61u ? 0u : TYPE63_INITIAL_BANK;
    type42_bank_mask = type42_bank_count - 1u;
    /* Check the actual uncached path while a normal loading error can still
     * be reported. An order-sensitive hash supplements CAR's additive sum.
     * Other mappers retain their existing admission and launch policy. */
    if (!type63_verify_fast_flash()) {
        if (type63_preflight_result == TYPE63_PREFLIGHT_TOO_SLOW)
            snprintf(error, 40, "Type63 slow: +%lu > +%u",
                     (unsigned long)type63_flash_extra_cycles,
                     TYPE63_FLASH_MAX_EXTRA_CYCLES);
        else if (type63_preflight_result == TYPE63_PREFLIGHT_TIMER_BUSY)
            strcpy(error, "Type63 timing probe unavailable");
        else if ((type63_preflight_result & TYPE63_PREFLIGHT_STATUS_MASK) ==
                 TYPE63_PREFLIGHT_SSI_MODE)
            snprintf(error, 40, "Type63 SSI %02lX=%08lX",
                     (unsigned long)(type63_preflight_result >> TYPE63_PREFLIGHT_REGISTER_SHIFT),
                     (unsigned long)type63_flash_extra_cycles);
        else if (type63_preflight_result == TYPE63_PREFLIGHT_SSI_TOO_SLOW)
            snprintf(error, 40, "Type63 SSI slow: +%lu > +%u",
                     (unsigned long)type63_flash_extra_cycles,
                     TYPE63_SSI_MAX_EXTRA_CYCLES);
        else strcpy(error, "Type63 fast flash integrity failed");
        goto failed;
    }
    type63_admission_checked = true;
    return true;
read_error:
    strcpy(error, "Type63 flash mapping/read failed");
failed:
    memset(cache_128k, 0, TYPE63_TABLE_BYTES);
    memset(type42_pages, 0, sizeof(type42_pages));
    type63_pages = NULL;
    type42_mapper_type = 0;
    type63_payload_hash = 0;
    type63_admission_checked = false;
    return false;
}

void type63_prepare_bus(void) {
    if (!type63_pages ||
        ((uintptr_t)type42_pages[0] & ~TYPE63_CACHED_BANK_FLAG) ==
            (uintptr_t)type63_pages) return;
    const unsigned bank_count = type42_mapper_type == 61u ? 128u : 256u;
    const uint8_t *seams[TYPE63_SEAM_COUNT] = {
        type42_pages[TYPE63_SEAM_SLOT],
        type42_pages[TYPE63_SEAM_SLOT + 1u],
        type42_pages[TYPE63_SEAM_SLOT + 2u],
        type42_pages[TYPE63_SEAM_SLOT + 3u],
        type42_pages[TYPE63_SEAM_SLOT + 4u]
    };
    const unsigned seam_count = type63_seam_count();
    /* Expand backwards so an unread raw entry is never overwritten. Cache
     * banks 0..3 and FE completely, including each 16-byte header seam.
     * All other banks contain only pre-encoded flash commands, even where a
     * seam sector also has a cached copy. Normalize and bias before encoding. */
    for (unsigned bank = bank_count; bank-- > 0;) {
        bool cached = type63_cached_bank(bank);
        for (unsigned half = 2; half-- > 0;)
            for (unsigned page = TYPE63_HALF_PAGES; page-- > 0;) {
                unsigned raw = bank * 32u + half * 16u + page;
                unsigned slot = bank * TYPE63_BANK_PAGES + half * TYPE63_HALF_PAGES + page;
                uintptr_t address = (uintptr_t)type63_pages[raw];
                if (!cached) {
                    for (unsigned seam = 0; seam < seam_count; ++seam)
                        if (raw == type63_seam_page(seam)) address = (uintptr_t)seams[seam];
                    if ((address >> 24) == 0x10u) address += 0x03000000u;
                    address = (((address - page * 512u) & 0x00ffffffu) << 8) | 0xa0u;
                } else address -= page * 512u;
                type63_pages[slot] = (const uint8_t *)address;
            }
    }
    for (unsigned bank = 0; bank < bank_count; ++bank) {
        uintptr_t map = (uintptr_t)(type63_pages + bank * TYPE63_BANK_PAGES);
        if (type63_cached_bank(bank)) map |= TYPE63_CACHED_BANK_FLAG;
        type42_pages[bank] = (const uint8_t *)map;
    }
    if (type42_mapper_type == 61u) type61_install_bus();
    else type63_install_bus();
}

bool type63_load_image(FIL *file, uint8_t *cache_128k, char error[40]) {
    return load_large_image(file, cache_128k, error, 63u);
}

bool type61_load_image(FIL *file, uint8_t *cache_128k, char error[40]) {
    return load_large_image(file, cache_128k, error, 61u);
}
