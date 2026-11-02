/* Exercise the production loader with the real upstream FatFs and a
 * fragmented simulated flash disk. This does not model Atari bus timing. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "type42_image.h"
static int testing_mpe;
static unsigned testing_cart_type = 42;
static bool test_load(FIL *f, uint8_t *c, char *e) {
    return testing_cart_type == 42 ? type42_load_image(f,c,e) :
        type42_load_standard_image(f,c,e,testing_cart_type);
}
#include "diskio.h"

#ifndef DISK_SECTORS
#define DISK_SECTORS 16384u
#endif
static uint8_t disk_bytes[DISK_SECTORS * 512];
static struct { uint8_t before[32], data[128*1024], after[32]; } guarded_cache;
#define cache guarded_cache.data
static unsigned mirror_comparisons, mirror_images, mirror_rejections;
static void guard_set(void) {
    memset(guarded_cache.before,0x69,sizeof guarded_cache.before);
    memset(guarded_cache.after,0x96,sizeof guarded_cache.after);
}
static void guard_check(void) {
    for(unsigned i=0;i<32;i++) {
        assert(guarded_cache.before[i]==0x69);
        assert(guarded_cache.after[i]==0x96);
    }
}
static unsigned permutation = 1, pointer_calls, fail_pointer_call;
static unsigned verified_files, verified_bytes, rejected_files;
static unsigned owner_mode, raw_offsets[2049];
static FATFS fs;

static uint8_t *disk_sector(unsigned sector) {
    assert(sector < DISK_SECTORS);
    return disk_bytes + ((sector * permutation) & (DISK_SECTORS - 1)) * 512;
}
const uint8_t *flash_fs_sector_pointer(uint32_t sector) {
    if (++pointer_calls == fail_pointer_call) return NULL;
    const uint8_t *p = sector < DISK_SECTORS ? disk_sector(sector) : NULL;
    if (p && pointer_calls <= 2049) raw_offsets[pointer_calls-1] = (unsigned)(p-disk_bytes);
    return p;
}
DSTATUS disk_initialize(BYTE p) { return p ? STA_NOINIT : 0; }
DSTATUS disk_status(BYTE p) { return p ? STA_NOINIT : 0; }
DRESULT disk_read(BYTE p, BYTE *buf, LBA_t s, UINT n) {
    if (p || s >= DISK_SECTORS || n > DISK_SECTORS - s) return RES_PARERR;
    for (UINT i = 0; i < n; ++i) memcpy(buf + i * 512, disk_sector(s + i), 512);
    return RES_OK;
}
DRESULT disk_write(BYTE p, const BYTE *buf, LBA_t s, UINT n) {
    if (p || s >= DISK_SECTORS || n > DISK_SECTORS - s) return RES_PARERR;
    for (UINT i = 0; i < n; ++i) memcpy(disk_sector(s + i), buf + i * 512, 512);
    return RES_OK;
}
DRESULT disk_ioctl(BYTE p, BYTE cmd, void *out) {
    if (p) return RES_PARERR;
    switch (cmd) {
        case CTRL_SYNC: return RES_OK;
        case GET_SECTOR_COUNT: *(LBA_t *)out = DISK_SECTORS; return RES_OK;
        case GET_SECTOR_SIZE: *(WORD *)out = 512; return RES_OK;
        case GET_BLOCK_SIZE: *(DWORD *)out = 1; return RES_OK;
        default: return RES_PARERR;
    }
}
static void make_disk(const uint8_t *data, size_t size, int fragmented) {
    uint8_t work[4096], fill[8192] = {0};
    FIL game, filler;
    MKFS_PARM options = { FM_FAT | FM_SFD, 1, 0, 0, 512 };
    assert(f_mount(NULL, "", 0) == FR_OK);
    memset(disk_bytes, 0, sizeof disk_bytes);
    permutation = fragmented ? 97 : 1;
    pointer_calls = fail_pointer_call = 0;
    assert(f_mkfs("", &options, work, sizeof work) == FR_OK);
    assert(f_mount(&fs, "", 1) == FR_OK);
    assert(f_open(&game, "GAME.CAR", FA_WRITE | FA_CREATE_ALWAYS) == FR_OK);
    assert(f_open(&filler, "FILLER.BIN", FA_WRITE | FA_CREATE_ALWAYS) == FR_OK);
    for (size_t offset = 0; offset < size;) {
        UINT wrote, amount = size - offset > 8192 ? 8192 : (UINT)(size - offset);
        assert(f_write(&game, data + offset, amount, &wrote) == FR_OK && wrote == amount);
        offset += amount;
        if (fragmented)
            assert(f_write(&filler, fill, sizeof fill, &wrote) == FR_OK && wrote == sizeof fill);
    }
    assert(f_close(&game) == FR_OK);
    assert(f_close(&filler) == FR_OK);
}

static void raw_bank_assertions(void) {
    if (testing_mpe || testing_cart_type != 42) return;
    for (unsigned b=0;b<type42_bank_count;b++) {
        unsigned first=b*16;int cached=1,raw=1;
        for (unsigned i=1;i<=16;i++) {
            if ((uintptr_t)type42_pages[first+i] != (uintptr_t)type42_pages[first]+i*512) cached=0;
            if (raw_offsets[first+i] != raw_offsets[first]+i*512) raw=0;
        }
        const uint8_t *expected=cached ? type42_pages[first]+16 : raw ? disk_bytes+raw_offsets[first]+16 : NULL;
        assert(type42_bank_base[b]==expected);
    }
}
static void map_entry(FILE *o,const uint8_t *p) {
    if (!p) fprintf(o,"[\"none\",0]");
    else if ((uintptr_t)p >= (uintptr_t)cache && (uintptr_t)p < (uintptr_t)(cache+sizeof cache))
        fprintf(o,"[\"sram\",%u]",(unsigned)(p-cache));
    else {
        assert((uintptr_t)p >= (uintptr_t)disk_bytes && (uintptr_t)p < (uintptr_t)(disk_bytes+sizeof disk_bytes));
        fprintf(o,"[\"flash\",%u]",(unsigned)(p-disk_bytes));
    }
}
static void dump_map(const uint8_t *data,int fragmented) {
    FILE *o=fopen(fragmented?"map-fragmented.json":"map-contiguous.json","w");assert(o);
    fprintf(o,"{\"cachePages\":256,\"fragmented\":%s,\"filePages\":[",fragmented?"true":"false");
    for(unsigned p=0;p<type42_file_pages;p++){if(p)fputc(',',o);map_entry(o,type42_pages[p]);}
    fprintf(o,"],\"rawPhysicalPages\":[");
    for(unsigned p=0;p<type42_file_pages;p++)fprintf(o,"%s%u",p?",":"",raw_offsets[p]);
    fprintf(o,"],\"bankBases\":[");
    for(unsigned b=0;b<type42_bank_count;b++){if(b)fputc(',',o);map_entry(o,type42_bank_base[b]);}
    fprintf(o,"],\"criticalBytes\":{\"A006\":[%u,%u,%u],\"AE98\":[%u,%u,%u]}}\n",
        data[22],data[23],data[24],data[16+0xe98],data[16+0xe99],data[16+0xe9a]);
    assert(!fclose(o));
}

static void check_image(const uint8_t *data, size_t size, int fragmented) {
    FIL game;
    char error[40] = {0};
    if (testing_mpe) memset(cache+122880,0xa5,8192);
    guard_set();
    make_disk(data, size, fragmented);
    assert(f_open(&game, "GAME.CAR", FA_READ) == FR_OK);
    if (!test_load(&game, cache, error)) {
        fprintf(stderr, "Unexpected load failure: %s\n", error);
        abort();
    }
    assert(f_close(&game) == FR_OK);
    guard_check();
    if (!testing_mpe && testing_cart_type==112) {
        for(unsigned bank=0;bank<64;bank++) for(unsigned low=0;low<256;low++) {
            assert(cache[114688+bank*256+low] == data[16+bank*8192+0x1500+low]);
            ++mirror_comparisons;
        }
        ++mirror_images;
    }
    unsigned cache_pages = 0, direct_banks = 0;
    const unsigned expected_banks = (testing_cart_type == 30 || testing_cart_type == 109) ? 32 : (testing_cart_type == 110 || testing_cart_type == 112) ? 64 : 128;
    assert(type42_bank_count == expected_banks);
    assert(type42_file_pages == expected_banks * 16 + 1);
    assert(type42_bank_mask == expected_banks - 1);
    assert(type42_initial_bank == (testing_cart_type == 42 ? 127 : 0));
    assert(type42_mapper_type == testing_cart_type);
    for (unsigned page = 0; page < type42_file_pages; ++page) {
        uintptr_t p = (uintptr_t)type42_pages[page];
        if (p >= (uintptr_t)cache && p < (uintptr_t)(cache + sizeof cache)) ++cache_pages;
    }
    assert(cache_pages == (testing_mpe ? 240 : testing_cart_type==112 ? 224 : TYPE42_CACHE_PAGES));
    if (!testing_mpe && (testing_cart_type==42 || testing_cart_type==75)) {
        for(unsigned p=0;p<type42_file_pages;p++) {
            if(p<239) assert(type42_pages[p]==cache+p*512);
            else if(p>=type42_file_pages-17)
                assert(type42_pages[p]==cache+(239+p-(type42_file_pages-17))*512);
            else assert(!((uintptr_t)type42_pages[p]>=(uintptr_t)cache &&
                          (uintptr_t)type42_pages[p]<(uintptr_t)(cache+sizeof cache)));
        }
        assert(type42_bank_base[127]==cache+239*512+16);
    }
    if (testing_mpe) {
        for (unsigned i=122880;i<sizeof cache;i++) assert(cache[i]==0xa5);
    }
    for (unsigned page = type42_file_pages; page < TYPE42_FILE_PAGES; ++page) assert(!type42_pages[page]);
    for (unsigned bank = type42_bank_count; bank < 128; ++bank) assert(!type42_bank_base[bank]);
    if (testing_cart_type != 42) assert(type42_bank_base[0] == cache + 16);
    if (testing_cart_type == 30) assert(type42_bank_base[1] == cache + 8192 + 16);
    for (unsigned bank = 0; bank < type42_bank_count; ++bank) {
        if (type42_bank_base[bank]) ++direct_banks;
        for (unsigned address = 0; address < 8192; ++address) {
            unsigned file_offset = 16 + bank * 8192 + address;
            assert(type42_pages[file_offset >> 9][file_offset & 511] == data[file_offset]);
            if (type42_bank_base[bank])
                assert(type42_bank_base[bank][address] == data[file_offset]);
            ++verified_bytes;
        }
    }
    assert(direct_banks >= (testing_mpe ? 14 : testing_cart_type==112 ? 13 : 15)); /* pinned tail, including initial bank 127 */
    assert(fragmented ? direct_banks < type42_bank_count : direct_banks > type42_bank_count - 4);
    raw_bank_assertions();
    if(owner_mode)dump_map(data,fragmented);
    ++verified_files;
}
static void check_rejected(const uint8_t *data, size_t size, unsigned fail_page) {
    FIL game;
    char error[40] = {0};
    guard_set();
    make_disk(data, size, 1);
    fail_pointer_call = fail_page;
    assert(f_open(&game, "GAME.CAR", FA_READ) == FR_OK);
    assert(!test_load(&game, cache, error));
    assert(error[0]);
    guard_check();
    assert(type42_mapper_type == 0);
    if (!testing_mpe && testing_cart_type==112) ++mirror_rejections;
    ++rejected_files;
    assert(f_close(&game) == FR_OK);
    for (unsigned i = 0; i < TYPE42_FILE_PAGES; ++i) assert(type42_pages[i] == NULL);
    for (unsigned i = 0; i < 128; ++i) assert(type42_bank_base[i] == NULL);
}
static void put_be32(uint8_t *p, uint32_t value) {
    p[0] = value >> 24; p[1] = value >> 16; p[2] = value >> 8; p[3] = value;
}
static void synthetic_image(uint8_t *image, unsigned cart_type) {
    testing_cart_type = cart_type;
    const unsigned payload = (cart_type == 30 || cart_type == 109) ? 262144 : (cart_type == 110 || cart_type == 112) ? 524288 : TYPE42_ROM_BYTES;
    const size_t size = payload + 16;
    memset(image, 0, 16);
    memcpy(image, "CART", 4);
    put_be32(image + 4, cart_type);
    uint32_t sum = 0;
    for (unsigned i = 0; i < payload; ++i) {
        image[i + 16] = (uint8_t)((i * 37) ^ (i >> 8) ^ (i >> 13));
        sum += image[i + 16];
    }
    put_be32(image + 8, sum);
    check_image(image, size, 0);
    check_image(image, size, 1);
    check_rejected(image, size - 1, 0);
    image[size] = 0xff;
    check_rejected(image, size + 1, 0);
    image[0] = 'X'; check_rejected(image, size, 0); image[0] = 'C';
    image[7] = 61; check_rejected(image, size, 0); image[7] = cart_type;
    image[4] = 1; check_rejected(image, size, 0); image[4] = 0;
    image[8] ^= 1; check_rejected(image, size, 0); image[8] ^= 1;
    image[600] ^= 1; check_rejected(image, size, 0); image[600] ^= 1;
    check_rejected(image, size, 17);
    if (cart_type==112) {
        const unsigned banks[]={0,31,63}, lows[]={0,239,240,255};
        for(unsigned b=0;b<3;b++) for(unsigned x=0;x<4;x++) {
            unsigned at=16+banks[b]*8192+0x1500+lows[x];
            image[at]^=1; check_rejected(image,size,0); image[at]^=1;
        }
        /* Fail obtaining each file sector forming the first/last mirror. */
        for(unsigned b=0;b<2;b++) for(unsigned part=10;part<=11;part++)
            check_rejected(image,size,(b?63:0)*16+part+1);
    }
    /* Finish admitted, so the next image really exercises a mapper change. */
    check_image(image, size, 1);
}
int main(int argc, char **argv) {
    uint8_t *image = malloc(TYPE42_ROM_BYTES + 17);
    assert(image);
    synthetic_image(image, 42);
    synthetic_image(image, 75);
    synthetic_image(image, 109);
    synthetic_image(image, 110);
    synthetic_image(image, 112);
    synthetic_image(image, 30);
    /* Loading another mapper after DCART must reset its D5-ROM mode. */
    synthetic_image(image, 110);
    synthetic_image(image, 42);
    for (int arg = 1; arg < argc; ++arg) {
        FILE *input = fopen(argv[arg], "rb");
        assert(input);
        size_t size = fread(image, 1, TYPE42_ROM_BYTES + 17, input);
        fclose(input);
        testing_mpe = memcmp(image,"A8M1",4)==0;
        testing_cart_type = testing_mpe ? 42 : image[7];
        owner_mode=testing_cart_type==42;
        check_image(image,size,0);
        check_image(image,size,1);
        owner_mode=0;
        if (testing_mpe) {
            const unsigned positions[]={0,7,12,8,600};
            for(unsigned k=0;k<5;k++) {
                image[positions[k]]^=1;
                check_rejected(image,size,0);
                image[positions[k]]^=1;
            }
            check_rejected(image,size-1,0);
            check_rejected(image,size+1,0);
            check_rejected(image,size,17);
        }
        printf("PASS unchanged image: %s\n", argv[arg]);
    }
    printf("PASS %u images, %u byte comparisons; %u rejection cases; real FatFs fragmentation\n",
           verified_files, verified_bytes, rejected_files);
    printf("MIRROR PASS %u images %u byte comparisons %u rejected admissions guard128K\n",mirror_images,mirror_comparisons,mirror_rejections);
    free(image);
    return 0;
}
