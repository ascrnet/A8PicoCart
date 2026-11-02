#include "type42_image.h"
#include "flash_fs.h"
#include <string.h>

const uint8_t *type42_pages[TYPE42_FILE_PAGES];
const uint8_t *type42_bank_base[128];
uint32_t type42_payload_checksum;
uint32_t type42_file_pages = TYPE42_FILE_PAGES;
uint32_t type42_bank_count = 128;
uint32_t type42_initial_bank = TYPE42_INITIAL_BANK;
uint32_t type42_bank_mask = 127;
uint32_t type42_mapper_type;

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static bool load_image(FIL *file, uint8_t *cache_128k, char error[40], bool mpe,
                       unsigned cart_type) {
    type42_mapper_type = 0;
    uint8_t sector[512];
    uint32_t checksum = 0, expected_checksum = 0;
    unsigned cache_page = 0;
    memset(type42_pages, 0, sizeof(type42_pages));
    memset(type42_bank_base, 0, sizeof(type42_bank_base));
    unsigned rom_bytes;
    switch (cart_type) {
        case 30: rom_bytes = 256u * 1024u; break;
        case 42: rom_bytes = TYPE42_ROM_BYTES; break;
        case 75: rom_bytes = TYPE42_ROM_BYTES; break;
        case 109: rom_bytes = 256u * 1024u; break;
        case 110: rom_bytes = 512u * 1024u; break;
        case 112: rom_bytes = 512u * 1024u; break;
        default:
            strcpy(error, "Unsupported flash CAR type");
            return false;
    }
    type42_file_pages = rom_bytes / 512 + 1;
    type42_bank_count = rom_bytes / 8192;
    type42_bank_mask = type42_bank_count - 1;
    type42_initial_bank = cart_type == 42 ? TYPE42_INITIAL_BANK : 0;
    if (f_size(file) != rom_bytes + TYPE42_HEADER_BYTES) {
        strcpy(error, mpe ? "MPE needs exactly 1MB+16 bytes" :
               cart_type == 30 ? "Type30 needs exactly 256KB+16 bytes" :
               (cart_type == 42 || cart_type == 75) ? "Atarimax needs exactly 1MB+16 bytes" :
               cart_type == 109 ? "Type109 needs exactly 256KB+16 bytes" :
               cart_type == 110 ? "Type110 needs exactly 512KB+16 bytes" :
                                  "Type112 needs exactly 512KB+16 bytes");
        return false;
    }
    if (f_lseek(file, 0) != FR_OK) {
        strcpy(error, "Type42 seek failed");
        return false;
    }
    for (unsigned page = 0; page < type42_file_pages; ++page) {
        const unsigned count = page == type42_file_pages - 1 ? 16 : 512;
        UINT got;
        /* A partial read makes FatFs set FIL.sect. A direct 512-byte read
         * bypasses that cache field, so must NOT be used to discover sectors. */
        if (f_read(file, sector, 1, &got) != FR_OK || got != 1) goto read_error;
        const uint8_t *physical = flash_fs_sector_pointer(file->sect);
        if (!physical) goto read_error;
        /* Retain a Type42 raw-bank candidate across all 17 file sectors.
         * The cache can split a physically contiguous bank (notably bank zero)
         * between SRAM and flash. Prefer a fully cached bank below; otherwise
         * this candidate avoids the fragmented lookup for contiguous flash.
         * Reuse the existing base table; the 128 KiB cache stays unchanged. */
        if (!mpe && (cart_type == 42 || cart_type == 75)) {
            const unsigned bank = page / 16, part = page % 16;
            if (part == 0) {
                if (page && type42_bank_base[bank - 1] &&
                    (uintptr_t)physical != (uintptr_t)type42_bank_base[bank - 1] - 16 + 8192)
                    type42_bank_base[bank - 1] = NULL;
                if (bank < type42_bank_count)
                    type42_bank_base[bank] = physical + 16;
            } else if (type42_bank_base[bank] &&
                       (uintptr_t)physical != (uintptr_t)type42_bank_base[bank] - 16 + part * 512) {
                type42_bank_base[bank] = NULL;
            }
        }
        if (f_read(file, sector + 1, count - 1, &got) != FR_OK || got != count - 1)
            goto read_error;
        if (page == 0) {
            if ((!mpe && (memcmp(sector, "CART", 4) || be32(sector + 4) != cart_type)) ||
                (mpe && (memcmp(sector, "A8M1", 4) || be32(sector + 4) != 1 ||
                         memcmp(sector + 12, "A8AG", 4)))) {
                strcpy(error, mpe ? "Invalid Atari MPE v1 package" :
                       cart_type == 30 ? "Invalid MegaCart CAR header" :
                       cart_type == 42 ? "Invalid Type42 CAR header" :
                       cart_type == 112 ? "Invalid DCart CAR header" : "Invalid J(atari)Cart CAR header");
                goto failed;
            }
            expected_checksum = be32(sector + 8);
        }
        for (unsigned i = page == 0 ? 16 : 0; i < count; ++i)
            checksum += sector[i];
        /* DCart's D5 mirror must not spend a serial flash transaction after
         * PHI2 rises. Reserve the last 16 KiB of the existing 128 KiB cache
         * for all 64 immutable B500-B5FF pages. CAR's 16-byte header splits
         * each mirror into 240 bytes of file sector 10 and 16 of sector 11.
         * These sectors are already read below the same checksum admission;
         * no extra FatFs operations, image writes or memory allocation. */
        if (!mpe && cart_type == 112) {
            const unsigned bank = page / 16, part = page % 16;
            if (bank < 64) {
                uint8_t *mirror = cache_128k + 112u * 1024u + bank * 256u;
                if (part == 10) memcpy(mirror, sector + 272, 240);
                else if (part == 11) memcpy(mirror + 240, sector, 16);
            }
        }
        /* Native Type42 caches its first 239 file pages and final 17 pages:
         * low program banks and the complete initial bank stay in 128 KiB.
         * MPE retains its first-page/tail profile. Other native mappers retain
         * their existing head/tail profiles. No game detection, ROM patching,
         * additional allocation, flash writes, or demand-load stalls. */
        /* MPE reserves the final 8 KiB for its response window; DCart uses
         * the final 16 KiB for the immutable mirrors populated above. */
        const unsigned head_pages = (cart_type == 42 || cart_type == 75) ? (mpe ? 1 : 239) : cart_type == 30 ? 33 : 17;
        const unsigned cache_pages = mpe ? 240 : cart_type == 112 ? 224 : TYPE42_CACHE_PAGES;
        if (page < head_pages || page >= type42_file_pages - (cache_pages - head_pages)) {
            uint8_t *cached = cache_128k + cache_page++ * 512;
            memcpy(cached, sector, count);
            if (count < 512) memset(cached + count, 0xff, 512 - count);
            type42_pages[page] = cached;
        } else {
            type42_pages[page] = physical;
        }
    }
    if (checksum != expected_checksum) {
        strcpy(error, mpe ? "MPE checksum mismatch" :
               cart_type == 30 ? "MegaCart CAR checksum mismatch" :
               cart_type == 112 ? "DCart CAR checksum mismatch" : "Type42 CAR checksum mismatch");
        goto failed;
    }
    for (unsigned bank = 0; bank < type42_bank_count; ++bank) {
        unsigned first = bank * 16;
        bool contiguous = true;
        /* The CAR header means each ROM bank touches 17 file sectors.
         * Integer comparisons avoid pointer arithmetic across allocations. */
        for (unsigned i = 1; i <= 16; ++i) {
            if ((uintptr_t)type42_pages[first + i] !=
                (uintptr_t)type42_pages[first] + i * 512)
                contiguous = false;
        }
        /* A contiguous cached representation wins over its raw candidate.
         * A genuine physical fragment has already cleared that candidate. */
        if (contiguous) type42_bank_base[bank] = type42_pages[first] + 16;
    }
    type42_payload_checksum = checksum;
    type42_mapper_type = cart_type;
    return true;
read_error:
    strcpy(error, "Type42 flash mapping/read failed");
failed:
    memset(type42_pages, 0, sizeof(type42_pages));
    memset(type42_bank_base, 0, sizeof(type42_bank_base));
    return false;
}

bool type42_load_image(FIL *file, uint8_t *cache_128k, char error[40]) {
    return load_image(file, cache_128k, error, false, 42);
}
bool type42_load_standard_image(FIL *file, uint8_t *cache_128k,
                                char error[40], unsigned cart_type) {
    return load_image(file, cache_128k, error, false, cart_type);
}
