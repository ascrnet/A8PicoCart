/* SPDX-License-Identifier: MIT
 * Real FatFs parser, fragmented 2 MiB images, exact 32-bit SRAM layout. */
#define DISK_SECTORS 32768u
#define main previous_mapper_fixture_main
#include "host_type42.c"
#undef main
#include "type63_image.h"
_Static_assert(sizeof(void *) == 4, "Use a 32-bit host compiler");
void type63_install_bus(void) { }
void type61_install_bus(void) { }
static unsigned probe_calls;
bool type63_verify_fast_flash(void) {
    uint32_t sum = 0, hash = 2166136261u;
    assert(type42_mapper_type == 61 && type42_bank_count == 128);
    for (unsigned p=0; p<4097; ++p)
        for (unsigned i=p?0:16; i<(p==4096?16:512); ++i) {
            uint8_t v=type63_pages[p][i]; sum+=v; hash=(hash^v)*16777619u;
        }
    assert(sum==type42_payload_checksum && hash==type63_payload_hash);
    ++probe_calls;
    return true;
}
static void check61(uint8_t *image, size_t size, int fragmented, unsigned fail, bool accept) {
    FIL game; char error[40]={0}; guard_set();
    make_disk(image,size,fragmented); fail_pointer_call=fail;
    assert(f_open(&game,"GAME.CAR",FA_READ)==FR_OK);
    bool ok=type61_load_image(&game,cache,error);
    assert(f_close(&game)==FR_OK); guard_check(); assert(ok==accept);
    if (!ok) { assert(error[0] && !type42_mapper_type && !type63_pages); ++rejected_files; return; }
    assert(type42_initial_bank==0 && type42_file_pages==4097 && type42_bank_mask==127);
    assert(type63_seam_count()==1 && type42_pages[TYPE63_SEAM_SLOT]);
    for(unsigned p=0;p<4097;++p) {
        uintptr_t at=(uintptr_t)type63_pages[p];
        bool pinned=at>=(uintptr_t)cache && at<(uintptr_t)(cache+sizeof cache);
        assert(pinned==(p<129));
    }
    for(unsigned at=16;at<size;++at) {
        assert(type63_pages[at/512][at%512]==image[at]); ++verified_bytes;
    }
    ++verified_files;
}
int main(int argc,char **argv) {
    const unsigned bytes=2097152u+16u;
    uint8_t *image=malloc(bytes+1); assert(image);
    for(unsigned i=16;i<bytes;++i)image[i]=(uint8_t)((i*73u)^(i>>9)^(i>>17));
    memcpy(image,"CART",4); put_be32(image+4,61); put_be32(image+12,0);
    uint32_t sum=0; for(unsigned i=16;i<bytes;++i)sum+=image[i]; put_be32(image+8,sum);
    for(unsigned fragmented=0;fragmented<2;++fragmented) {
        check61(image,bytes,fragmented,0,true);
        const unsigned positions[]={0,4,5,6,7,8,600,bytes-1};
        for(unsigned k=0;k<sizeof positions/sizeof positions[0];++k) {
            image[positions[k]]^=1; check61(image,bytes,fragmented,0,false); image[positions[k]]^=1;
        }
        check61(image,bytes-1,fragmented,0,false); check61(image,bytes+1,fragmented,0,false);
        for(unsigned p=1;p<=4097;p+=512)check61(image,bytes,fragmented,p,false);
    }
    for(int a=1;a<argc;++a) {
        FILE *f=fopen(argv[a],"rb"); assert(f);
        assert(fread(image,1,bytes+1,f)==bytes && feof(f)); fclose(f);
        check61(image,bytes,0,0,true); check61(image,bytes,1,0,true);
    }
    printf("PASS Type61: %u images, %u byte comparisons, %u rejection cases, %u probes; ABI32 guard128K real FatFs fragmentation\n",
           verified_files,verified_bytes,rejected_files,probe_calls);
    free(image); return 0;
}
