/* SPDX-License-Identifier: MIT
 * Reuse the real FatFs disk/fragmentation fixture, with a larger test disk.
 * Require the real 32-bit pointer layout so the fixed 128 KiB table/cache
 * split matches the RP2040. Never substitute a larger host pointer table. */
#define DISK_SECTORS 32768u
#define main previous_mapper_fixture_main
#define flash_fs_sector_pointer original_flash_fs_sector_pointer
#include "host_type42.c"
#undef main
#undef flash_fs_sector_pointer
#include "type63_image.h"
_Static_assert(sizeof(void *) == 4 && sizeof(uintptr_t) == 4,
               "Type63 host qualification requires an actual 32-bit ABI");

/* Parser-only host fixture: it never activates the SRAM bus loop. The linked
 * ARM bus fixture independently checks the real install/copy and activation. */
void type63_install_bus(void) { }
void type61_install_bus(void) { }

static const uint8_t *original_seams[TYPE63_SEAM_COUNT];
static unsigned expected_extra, hint_cases;
static unsigned expected_seam(unsigned i) {
    const unsigned fixed[3] = {128u,8128u,8160u};
    return i < 3u ? fixed[i] : expected_extra * 32u + (i == 4u ? 32u : 0u);
}
const uint8_t *flash_fs_sector_pointer(uint32_t sector) {
    const uint8_t *physical = original_flash_fs_sector_pointer(sector);
    for (unsigned i=0;i<(expected_extra?5u:3u);++i)
        if (pointer_calls == expected_seam(i)+1u) original_seams[i]=physical;
    return physical;
}

/* This host fixture checks FatFs, map construction, metadata and rejection
 * cleanup. The linked ARM probe fixture separately executes the real timer,
 * divider, ordered integrity check and latency gate. */
static unsigned forced_preflight, preflight_calls;
static uint32_t forced_ssi_value;
bool type63_verify_fast_flash(void) {
    uint32_t sum = 0, hash = 2166136261u;
    assert(type42_mapper_type == 63 && type63_pages);
    for (unsigned page = 0; page < TYPE63_FILE_PAGES; ++page) {
        unsigned end = page == TYPE63_FILE_PAGES - 1 ? 16 : 512;
        for (unsigned i = page ? 0 : 16; i < end; ++i) {
            uint8_t byte = type63_pages[page][i];
            sum += byte;
            hash = (hash ^ byte) * 16777619u;
        }
    }
    assert(sum == type42_payload_checksum && hash == type63_payload_hash);
    type63_preflight_result = forced_preflight;
    type63_flash_extra_cycles = (forced_preflight & TYPE63_PREFLIGHT_STATUS_MASK) ==
        TYPE63_PREFLIGHT_SSI_MODE ? forced_ssi_value :
        forced_preflight == TYPE63_PREFLIGHT_SSI_TOO_SLOW
            ? TYPE63_SSI_MAX_EXTRA_CYCLES + 1u : TYPE63_FLASH_MAX_EXTRA_CYCLES +
                (forced_preflight == TYPE63_PREFLIGHT_TOO_SLOW);
    ++preflight_calls;
    return !forced_preflight;
}

static void check63(uint8_t *data, size_t size, int fragmented, unsigned fail_page, bool accept) {
    FIL game;
    char error[40] = {0};
    memset(original_seams, 0, sizeof original_seams);
    guard_set();
    make_disk(data, size, fragmented);
    fail_pointer_call = fail_page;
    assert(f_open(&game, "GAME.CAR", FA_READ) == FR_OK);
    bool ok = type63_load_image(&game, cache, error);
    assert(f_close(&game) == FR_OK);
    guard_check();
    assert(ok == accept);
    if (!accept) {
        assert(error[0] && type42_mapper_type == 0 && type63_pages == NULL);
        assert(!type63_payload_hash);
        if (forced_preflight == TYPE63_PREFLIGHT_TOO_SLOW) {
            char expected[40];
            snprintf(expected, sizeof expected, "Type63 slow: +%u > +%u",
                     TYPE63_FLASH_MAX_EXTRA_CYCLES + 1, TYPE63_FLASH_MAX_EXTRA_CYCLES);
            assert(!strcmp(error, expected));
        }
        else if (forced_preflight == TYPE63_PREFLIGHT_TIMER_BUSY)
            assert(!strcmp(error, "Type63 timing probe unavailable"));
        else if (forced_preflight == TYPE63_PREFLIGHT_INTEGRITY)
            assert(!strcmp(error, "Type63 fast flash integrity failed"));
        else if ((forced_preflight & TYPE63_PREFLIGHT_STATUS_MASK) ==
                 TYPE63_PREFLIGHT_SSI_MODE) {
            char expected[40];
            snprintf(expected, sizeof expected, "Type63 SSI %02lX=%08lX",
                     (unsigned long)(forced_preflight >> TYPE63_PREFLIGHT_REGISTER_SHIFT),
                     (unsigned long)forced_ssi_value);
            assert(!strcmp(error, expected));
        }
        else if (forced_preflight == TYPE63_PREFLIGHT_SSI_TOO_SLOW) {
            char expected[40];
            snprintf(expected, sizeof expected, "Type63 SSI slow: +%u > +%u",
                     TYPE63_SSI_MAX_EXTRA_CYCLES + 1u, TYPE63_SSI_MAX_EXTRA_CYCLES);
            assert(!strcmp(error, expected));
        }
        for (unsigned p = 0; p < TYPE42_FILE_PAGES; ++p) assert(!type42_pages[p]);
        ++rejected_files;
        return;
    }
    assert(type42_mapper_type == 63 && type42_initial_bank == 254);
    assert(type42_bank_count == 256 && type42_file_pages == 8193);
    assert((const void *)type63_pages == (const void *)cache);
    unsigned pinned = 0, unique_count = 0;
    uintptr_t unique[TYPE63_CACHE_PAGES];
    assert(type63_extra_cached_bank()==expected_extra);
    for (unsigned p = 0; p < TYPE63_FILE_PAGES; ++p) {
        uintptr_t ptr = (uintptr_t)type63_pages[p];
        bool cached = ptr >= (uintptr_t)cache && ptr < (uintptr_t)(cache + sizeof cache);
        assert(cached == (p < TYPE63_HEAD_CACHE_PAGES ||
               (p >= 8128u && p <= 8160u) ||
               (expected_extra && p>=expected_extra*32u && p<=expected_extra*32u+32u)));
        if (cached) {
            assert(ptr >= (uintptr_t)cache + TYPE63_TABLE_BYTES);
            assert(ptr + 512 <= (uintptr_t)(cache + sizeof cache));
            ++pinned;
            unsigned i=0;while(i<unique_count && unique[i]!=ptr)++i;
            if(i==unique_count){assert(unique_count<TYPE63_CACHE_PAGES);unique[unique_count++]=ptr;}
        }
    }
    assert(pinned==(expected_extra?195u-((expected_extra==4u||expected_extra==253u)?1u:0u):162u));
    if(!expected_extra)assert(unique_count==162u); /* no dedup for legacy images */
    assert(type63_seam_count()==(expected_extra?5u:3u));
    for (unsigned seam = 0; seam < type63_seam_count(); ++seam) {
        assert(original_seams[seam]);
        assert(type42_pages[TYPE63_SEAM_SLOT + seam] == original_seams[seam]);
        assert(original_seams[seam] != type63_pages[expected_seam(seam)]);
        assert(!memcmp(original_seams[seam], type63_pages[expected_seam(seam)], 512));
    }
    for (unsigned bank = 0; bank < 256; ++bank) {
        assert(!type42_pages[bank]); /* prepare fills the biased half maps */
        for (unsigned offset = 0; offset < 16384; ++offset) {
            unsigned at = 16 + bank * 16384 + offset;
            assert(type63_pages[at / 512][at % 512] == data[at]);
            ++verified_bytes;
        }
    }
    ++verified_files;
}

/* Independent format/limit controls, executing the real parser and FatFs. */
static uint32_t crc_hint(const uint8_t *p,unsigned n){
    uint32_t c=0xffffffffu;while(n--){c^=*p++;for(unsigned k=0;k<8;++k)c=(c>>1)^((c&1u)?0xedb88320u:0);}return ~c;
}
static void sum_header(uint8_t *data){uint32_t n=0;for(unsigned i=16;i<TYPE63_ROM_BYTES+16u;++i)n+=data[i];put_be32(data+8,n);}
static uint8_t *hint_record(uint8_t *data,unsigned bank){
    uint8_t *h=data+16u+255u*16384u;memset(h,0,20);memcpy(h,"A8C63HNT",8);h[8]=1;h[9]=20;h[10]=1;h[11]=bank;
    uint32_t c=crc_hint(h,16);for(unsigned k=0;k<4;++k)h[16+k]=(uint8_t)(c>>(8*k));sum_header(data);return h;
}
static void synthetic63(uint8_t *data){
    for(unsigned i=0;i<TYPE63_ROM_BYTES+16u;++i)data[i]=(uint8_t)((i*37)^(i>>8)^(i>>14)^(i>>20));
    memcpy(data,"CART",4);put_be32(data+4,63);put_be32(data+12,0);sum_header(data);
}
static void check_hint_cases(uint8_t *data,size_t size){
    /* Exact fit:195 selected raw pages,5 uniform00+4 uniformFF =>188 slots. */
    synthetic63(data);for(unsigned p=1;p<=9;++p)memset(data+p*512u,p<=5?0:255,512);
    hint_record(data,24);expected_extra=24;check63(data,size,1,0,true);++hint_cases;
    unsigned before=preflight_calls;
    /* One fewer shared FF page needs189 slots: must reject before preflight. */
    for(unsigned i=0;i<512;++i)data[9*512u+i]=(uint8_t)i;
    sum_header(data);check63(data,size,1,0,false);assert(preflight_calls==before);++hint_cases;
    /* Both uniform values alias safely, including extra-bank boundary seams. */
    for(unsigned p=0;p<TYPE63_FILE_PAGES;++p)memset(data+p*512u,(p&1u)?255:0,p==TYPE63_FILE_PAGES-1u?16:512);
    memcpy(data,"CART",4);put_be32(data+4,63);put_be32(data+12,0);
    for(unsigned bank=4;bank<=253;bank+=(bank==4?20:229)){
        hint_record(data,bank);expected_extra=bank;check63(data,size,0,0,true);check63(data,size,1,0,true);hint_cases+=2;
    }
    /* Invalid signatures remain ordinary legacy data; malformed SIGNED records reject. */
    uint8_t *h=hint_record(data,24);expected_extra=24;
    const unsigned offsets[]={8,9,10,12,13,14,15,16};
    for(unsigned k=0;k<sizeof offsets/sizeof offsets[0];++k){
        unsigned at=offsets[k];uint8_t prior=h[at];h[at]^=1;
        if(at!=16){uint32_t c=crc_hint(h,16);for(unsigned j=0;j<4;++j)h[16+j]=(uint8_t)(c>>(8*j));}
        sum_header(data);check63(data,size,1,0,false);++hint_cases;h[at]=prior;hint_record(data,24);
    }
    const unsigned bad_banks[]={0,1,2,3,254,255};
    for(unsigned k=0;k<6;++k){hint_record(data,bad_banks[k]);check63(data,size,1,0,false);++hint_cases;}
    hint_record(data,24);h[0]^=1;sum_header(data);expected_extra=0;check63(data,size,1,0,true);++hint_cases;
    /* A hinted load followed by legacy must clear the stored bank and retain162 allocation. */
    hint_record(data,24);expected_extra=24;check63(data,size,1,0,true);++hint_cases;
    memset(h,255,20);sum_header(data);expected_extra=0;check63(data,size,1,0,true);++hint_cases;
}

int main(int argc, char **argv) {
    size_t size = TYPE63_ROM_BYTES + 16u;
    uint8_t *data = malloc(size + 1);
    assert(data);
    memcpy(data, "CART", 4); put_be32(data+4, 63); put_be32(data+12, 0);
    uint32_t sum = 0;
    for (unsigned i = 0; i < TYPE63_ROM_BYTES; ++i) {
        data[16+i] = (uint8_t)((i*37) ^ (i>>8) ^ (i>>14) ^ (i>>20));
        sum += data[16+i];
    }
    put_be32(data+8, sum);
    for (int fixture = 0; fixture < argc; ++fixture) {
        if (fixture) {
            FILE *input = fopen(argv[fixture], "rb"); assert(input);
            assert(fread(data, 1, size+1, input) == size); fclose(input);
        }
        expected_extra=0;
        if(!memcmp(data+16u+255u*16384u,"A8C63HNT",8))expected_extra=data[16u+255u*16384u+11u];
        check63(data,size,0,0,true);
        check63(data,size,1,0,true);
        for (forced_preflight = TYPE63_PREFLIGHT_INTEGRITY;
             forced_preflight <= TYPE63_PREFLIGHT_SSI_TOO_SLOW; ++forced_preflight)
            check63(data,size,1,0,false);
        const unsigned ssi_offsets[] = {0,4,8,0x10,0x4c,0xf4,0xf0,0x14};
        for (unsigned i = 0; i < sizeof ssi_offsets / sizeof ssi_offsets[0]; ++i) {
            forced_preflight = TYPE63_PREFLIGHT_SSI_MODE |
                (ssi_offsets[i] << TYPE63_PREFLIGHT_REGISTER_SHIFT);
            forced_ssi_value = i & 1u ? 7u : 0x89abcdefu;
            check63(data,size,1,0,false);
        }
        forced_ssi_value = 0;
        forced_preflight = TYPE63_PREFLIGHT_OK;
        check63(data,size,1,0,true);
        check63(data,size-1,1,0,false);
        data[size]=0xff; check63(data,size+1,1,0,false);
        const unsigned corrupt[] = {0,4,7,8,16,511,512,16+254*16384,16+255*16384};
        for(unsigned k=0;k<sizeof corrupt/sizeof corrupt[0];++k) {
            data[corrupt[k]]^=1; check63(data,size,1,0,false); data[corrupt[k]]^=1;
        }
        const unsigned missing[] = {1,2,158,8129,8161,8193};
        for(unsigned k=0;k<sizeof missing/sizeof missing[0];++k)
            check63(data,size,1,missing[k],false);
        check63(data,size,1,0,true);
        /* A subsequent smaller mapper rebuilds its own tables and cache. */
        synthetic_image(data,30);
    }
    check_hint_cases(data,size);
    printf("PASS Type63 %u images %u byte comparisons %u rejection cases; real FatFs fragmentation; guard128K; ABI32; cache162 default; physicalSeams3 default/5 hinted; max188; %u hint cases; %u admission preflights\n",
           verified_files,verified_bytes,rejected_files,hint_cases,preflight_calls);
    free(data);
    return 0;
}
