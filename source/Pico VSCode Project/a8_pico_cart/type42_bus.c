#include "pico/stdlib.h"
#include "hardware/sync.h"
#include "hardware/structs/ssi.h"
#include "hardware/regs/ssi.h"
#include "hardware/structs/systick.h"
#include "hardware/structs/scb.h"
#include "type42_image.h"
#include "type63_image.h"
#include <string.h>

#ifndef A8_TYPE42_FLASH_DIVIDER
#define A8_TYPE42_FLASH_DIVIDER 2
#endif
#if A8_TYPE42_FLASH_DIVIDER != 2 && A8_TYPE42_FLASH_DIVIDER != 4
#error A8_TYPE42_FLASH_DIVIDER must be 2 or 4
#endif

#define DATA_MASK 0x001fe000u
#define CCTL_MASK 0x00200000u
#define PHI2_MASK 0x00400000u
#define RW_MASK   0x00800000u
#define S5_MASK   0x02000000u
#define RD4_MASK  0x04000000u
#define RD5_MASK  0x08000000u

/* Debugger-visible count of reads discarded because address/select changed.
 * Neither zero nor nonzero establishes electrical timing acceptance. */
volatile uint32_t type42_stale_reads;
void type42_bus_loop(const uint8_t **pages, const uint8_t **bases) __attribute__((noreturn));
void dcart_bus_loop(const uint8_t **pages, const uint8_t **bases) __attribute__((noreturn));
void megacart_bus_loop(const uint8_t **pages, const uint8_t **bases) __attribute__((noreturn));
void type42_start_bus(const uint8_t **pages, const uint8_t **bases) __attribute__((noreturn));

/* Before the menu launches the cart, test the actual game's uncached flash
 * bytes at the experimental speed. The Atari is still in its existing menu
 * RAM polling stub here. Restore the menu divider before returning. This
 * separates flash data integrity from the still-unproven bus deadline. */
bool __attribute__((optimize("Os"))) __not_in_flash_func(type42_verify_fast_flash)(void) {
    if (type42_mapper_type == 63 || type42_mapper_type == 61)
        return type63_admission_checked || type63_verify_fast_flash();
    uint32_t irq = save_and_disable_interrupts();
    uint32_t divider = ssi_hw->baudr;
    while (ssi_hw->sr & SSI_SR_BUSY_BITS) { }
    ssi_hw->ssienr = 0;
    ssi_hw->baudr = A8_TYPE42_FLASH_DIVIDER;
    ssi_hw->ssienr = 1;
    __dsb();
    uint32_t checksum = 0;
    for (unsigned bank = 0; bank < type42_bank_count; ++bank) {
        uintptr_t base = (uintptr_t)type42_bank_base[bank];
        /* Follow the bytes the bus serves, including CAR's header seam.
         * This one-time preflight favors a compact SRAM loop over speed. */
        for (unsigned offset = 0; offset < 8192; ++offset) {
            uintptr_t address = base + offset;
            if (!base) {
                unsigned file_offset = 16 + bank * 8192 + offset;
                address = (uintptr_t)type42_pages[file_offset / 512] + file_offset % 512;
            }
            if ((address >> 24) == 0x10)
                address += 0x03000000u; /* uncached, nonallocating XIP alias */
            checksum += *(const volatile uint8_t *)address;
        }
    }
    while (ssi_hw->sr & SSI_SR_BUSY_BITS) { }
    ssi_hw->ssienr = 0;
    ssi_hw->baudr = divider;
    ssi_hw->ssienr = 1;
    __dsb();
    __isb();
    restore_interrupts(irq);
    return checksum == type42_payload_checksum;
}

void type42_prepare_bus(void) {
    if (type42_mapper_type == 63 || type42_mapper_type == 61) { type63_prepare_bus(); return; }
    /* v0.3: bypass XIP cache for bus reads, just as the preflight does.
     * A normal cache miss allocates an eight-byte line; the no-cache,
     * no-allocation alias avoids that refill and cache-history dependence.
     * Convert while the menu is still polling, before launch. Leave
     * the immutable SRAM cache and NULL fragmented-bank markers untouched.
     * The loader rebuilds both tables whenever another image is loaded. */
    for (unsigned page = 0; page < type42_file_pages; ++page) {
        uintptr_t address = (uintptr_t)type42_pages[page];
        if (address >= 0x10000000u && address < 0x11000000u)
            type42_pages[page] = (const uint8_t *)(address + 0x03000000u);
    }
    for (unsigned bank = 0; bank < type42_bank_count; ++bank) {
        uintptr_t address = (uintptr_t)type42_bank_base[bank];
        if (address >= 0x10000000u && address < 0x11000000u)
            type42_bank_base[bank] = (const uint8_t *)(address + 0x03000000u);
    }
}

void emulate_type42(void) {
    save_and_disable_interrupts();
    sio_hw->gpio_oe_clr = DATA_MASK;
    if (type42_mapper_type == 61) {
        sio_hw->gpio_set = RD4_MASK | RD5_MASK;
        type61_bus_loop(type63_pages, type42_pages);
    }
    if (type42_mapper_type == 63) {
        sio_hw->gpio_set = RD4_MASK | RD5_MASK;
        type63_bus_loop(type63_pages, type42_pages);
    }
    if (type42_mapper_type == 30) {
        sio_hw->gpio_set = RD4_MASK | RD5_MASK;
        megacart_bus_loop(type42_pages, type42_bank_base);
    }
    sio_hw->gpio_clr = RD4_MASK;
    sio_hw->gpio_set = RD5_MASK;
    /* One-time setup runs at the menu's normal flash divider. Each assembly
     * entry branches to SRAM before changing SSI, then never returns here. */
    if (type42_mapper_type == 112) dcart_bus_loop(type42_pages, type42_bank_base);
    type42_start_bus(type42_pages, type42_bank_base);
}

/* Both the SRAM reference and every payload byte use this exact three-load
 * sequence. No interrupt, flash instruction or flash literal may intervene.
 * SysTick runs at the processor clock and wraps after 24 bits. */
static inline __attribute__((always_inline)) uint8_t type63_timed_byte(
        uintptr_t address, uint32_t *cycles) {
    uint32_t before, byte, after;
    const volatile uint32_t *timer = &systick_hw->cvr;
    __asm volatile (
        "ldr %0, [%3]\n"
        "ldrb %1, [%4]\n"
        "ldr %2, [%3]\n"
        : "=&l" (before), "=&l" (byte), "=&l" (after)
        : "l" (timer), "l" (address)
        : "memory");
    *cycles = (before - after) & 0x00ffffffu;
    return (uint8_t)byte;
}

/* Measure the SSI register bridge separately from serial flash latency.
 * Reading SR never starts a transaction or consumes a FIFO entry. */
static inline __attribute__((always_inline)) uint32_t type63_register_cycles(uintptr_t address) {
    uint32_t before, value, after;
    const volatile uint32_t *timer = &systick_hw->cvr;
    __asm volatile (
        "ldr %0, [%3]\n"
        "ldr %1, [%4]\n"
        "ldr %2, [%3]\n"
        : "=&l" (before), "=&l" (value), "=&l" (after)
        : "l" (timer), "l" (address) : "memory");
    return (before - after) & 0x00ffffffu;
}

/* Temporarily copied into the inactive bank-table tail, then replaced by the
 * bus loop. The build checks size, alignment and absence of external calls.
 * All references are local relative branches or absolute literal addresses. */
bool __attribute__((noinline, noclone, optimize("Os"), aligned(4)))
type63_flash_probe_impl(void) {
    type63_preflight_result = TYPE63_PREFLIGHT_INTEGRITY;
    type63_flash_extra_cycles = 0;
    if ((type42_mapper_type != 63 && type42_mapper_type != 61) || !type63_pages ||
        ((uintptr_t)type42_pages[0] & ~(uintptr_t)1) == (uintptr_t)type63_pages) return false;
    /* DFS_32 controls frame width. Legacy DFS[3:0] is invalid on RP2040;
     * writes have no effect, so its readback cannot identify a protocol.
     * XIP_CMD belongs to automatic XIP transfers. The manual reader supplies
     * its own complete address/mode word through DR0; the full XIP integrity
     * probe below separately checks the automatic path. Ignore reserved bits,
     * keep every active direct-transfer guard, and report the first failure. */
    uint32_t setting, rejected_register;
#define REQUIRE_SSI_MODE(field, offset, condition) do { \
    setting = ssi_hw->field; \
    if (!(condition)) { rejected_register = (offset); goto ssi_unsupported; } \
} while (0)
    REQUIRE_SSI_MODE(ctrlr0, SSI_CTRLR0_OFFSET,
        (setting & (SSI_CTRLR0_BITS & ~SSI_CTRLR0_DFS_BITS)) == 0x005f0300u);
    REQUIRE_SSI_MODE(ctrlr1, SSI_CTRLR1_OFFSET, (setting & SSI_CTRLR1_BITS) == 0);
    REQUIRE_SSI_MODE(ssienr, SSI_SSIENR_OFFSET, (setting & SSI_SSIENR_BITS) == 1);
    REQUIRE_SSI_MODE(ser, SSI_SER_OFFSET, (setting & SSI_SER_BITS) == 1);
    REQUIRE_SSI_MODE(dmacr, SSI_DMACR_OFFSET, (setting & SSI_DMACR_BITS) == 0);
    REQUIRE_SSI_MODE(spi_ctrlr0, SSI_SPI_CTRLR0_OFFSET,
        (setting & (SSI_SPI_CTRLR0_BITS & ~SSI_SPI_CTRLR0_XIP_CMD_BITS)) == 0x00002022u);
    REQUIRE_SSI_MODE(rx_sample_dly, SSI_RX_SAMPLE_DLY_OFFSET,
        (setting & SSI_RX_SAMPLE_DLY_BITS) == 1);
    REQUIRE_SSI_MODE(baudr, SSI_BAUDR_OFFSET,
        (setting & SSI_BAUDR_BITS) == 2 || (setting & SSI_BAUDR_BITS) == 4);
#undef REQUIRE_SSI_MODE
    uint32_t irq = save_and_disable_interrupts();
    uint32_t control = systick_hw->csr & 7u;
    /* Do not borrow a running counter, its interrupt, or a pending exception.
     * The protected launcher normally leaves SysTick stopped. Restoring a
     * live counter's phase would be impossible by writing CVR. */
    if ((control & 3u) || (scb_hw->icsr & M0PLUS_ICSR_PENDSTSET_BITS) ||
        (scb_hw->icsr & 0x1ffu) == 15u) {
        type63_preflight_result = TYPE63_PREFLIGHT_TIMER_BUSY;
        restore_interrupts(irq);
        return false;
    }
    uint32_t reload = systick_hw->rvr;
    uint32_t divider = ssi_hw->baudr;
    while (ssi_hw->sr & SSI_SR_BUSY_BITS) { }
    ssi_hw->ssienr = 0;
    ssi_hw->baudr = A8_TYPE42_FLASH_DIVIDER;
    ssi_hw->ssienr = 1;
    __dsb();
    systick_hw->rvr = 0x00ffffffu;
    systick_hw->cvr = 0;
    systick_hw->csr = 5; /* ENABLE, processor CLKSOURCE, no interrupt */
    __dsb();
    uint32_t reference = 0x00ffffffu;
    for (unsigned i = 0; i < 64; ++i) {
        uint32_t cycles;
        (void)type63_timed_byte((uintptr_t)&type63_payload_hash, &cycles);
        if (cycles < reference) reference = cycles;
    }
    uint32_t register_reference = 0x00ffffffu, register_maximum = 0;
    for (unsigned i = 0; i < 64; ++i) {
        uint32_t cycles = type63_register_cycles((uintptr_t)&type63_payload_hash);
        if (cycles < register_reference) register_reference = cycles;
        cycles = type63_register_cycles((uintptr_t)&ssi_hw->sr);
        if (cycles > register_maximum) register_maximum = cycles;
    }
    uint32_t register_extra = register_maximum > register_reference ?
        register_maximum - register_reference : 0;
    if (register_extra > TYPE63_SSI_MAX_EXTRA_CYCLES) {
        type63_flash_extra_cycles = register_extra;
        type63_preflight_result = TYPE63_PREFLIGHT_SSI_TOO_SLOW;
        goto restore_probe;
    }
    uint32_t checksum = 0, hash = 2166136261u, maximum = 0;
    unsigned flash_pages = 0;
    const unsigned file_pages = type42_mapper_type == 61u ? 4097u : TYPE63_FILE_PAGES;
    for (unsigned page = 0; page < file_pages; ++page) {
        uintptr_t address = (uintptr_t)type63_pages[page];
        if ((address >> 24) == 0x10) address += 0x03000000u;
        bool flash = (address >> 24) == 0x13;
        if (flash) ++flash_pages;
        unsigned end = page == file_pages - 1 ? 16 : 512;
        for (unsigned i = page ? 0 : 16; i < end; ++i) {
            uint32_t cycles;
            uint8_t byte = type63_timed_byte(address + i, &cycles);
            checksum += byte;
            hash = (hash ^ byte) * 16777619u;
            if (flash && cycles > maximum) maximum = cycles;
        }
    }
    /* Cached seams also feed neighbouring flash banks. Check the retained
     * physical originals without replacing the cached full-payload hash. */
    for (unsigned seam = 0; seam < type63_seam_count(); ++seam) {
        unsigned page = type63_seam_page(seam);
        uintptr_t address = (uintptr_t)type42_pages[TYPE63_SEAM_SLOT + seam];
        if ((address >> 24) == 0x10) address += 0x03000000u;
        const volatile uint8_t *cached = type63_pages[page];
        for (unsigned i = 0; i < 512; ++i) {
            uint32_t cycles;
            uint8_t byte = type63_timed_byte(address + i, &cycles);
            if (cycles > maximum) maximum = cycles;
            if (byte != cached[i]) goto restore_probe;
        }
    }
    type63_flash_extra_cycles = maximum > reference ? maximum - reference : 0;
    if (!flash_pages || checksum != type42_payload_checksum || hash != type63_payload_hash)
        goto restore_probe;
    if (type63_flash_extra_cycles > TYPE63_FLASH_MAX_EXTRA_CYCLES) {
        type63_preflight_result = TYPE63_PREFLIGHT_TOO_SLOW;
        goto restore_probe;
    }
    type63_preflight_result = TYPE63_PREFLIGHT_OK;
restore_probe:
    systick_hw->csr = 0;
    systick_hw->rvr = reload;
    systick_hw->cvr = 0;
    systick_hw->csr = control;
    while (ssi_hw->sr & SSI_SR_BUSY_BITS) { }
    ssi_hw->ssienr = 0;
    ssi_hw->baudr = divider;
    ssi_hw->ssienr = 1;
    __dsb();
    __isb();
    restore_interrupts(irq);
    return type63_preflight_result == TYPE63_PREFLIGHT_OK;
ssi_unsupported:
    type63_flash_extra_cycles = setting;
    type63_preflight_result = TYPE63_PREFLIGHT_SSI_MODE |
        (rejected_register << TYPE63_PREFLIGHT_REGISTER_SHIFT);
    return false;
}

bool type63_verify_fast_flash(void) {
    _Static_assert(TYPE63_PROBE_COPY_BYTES <= (TYPE63_HINT_SLOT - 256u) * sizeof(type42_pages[0]),
                   "Type63 probe must fit the inactive bank-table tail");
    uintptr_t original = (uintptr_t)type63_flash_probe_impl & ~(uintptr_t)1;
    uint8_t *copy = (uint8_t *)(type42_pages + 256);
    memcpy(copy, (const void *)original, TYPE63_PROBE_COPY_BYTES);
    __dsb();
    __isb();
    return ((bool (*)(void))((uintptr_t)copy | 1u))();
}

/* Called only after admission and map preparation, before the launch ACK.
 * The build checks the copied section fits before the three seam pointers.
 * Keep flash-source refills out of the short post-FF activation interval. */
void type63_install_bus(void) {
    extern const uint8_t type63_steady_loop[];
    extern const uint8_t type63_steady_loop_end[];
    uintptr_t begin = (uintptr_t)type63_steady_loop & ~(uintptr_t)1;
    size_t bytes = (uintptr_t)type63_steady_loop_end - begin;
    memcpy((void *)(type42_pages + 256), (const void *)begin, bytes);
    __dsb();
    __isb();
}

void type61_install_bus(void) {
    extern const uint8_t type61_steady_loop[], type61_steady_loop_end[];
    uintptr_t begin = (uintptr_t)type61_steady_loop & ~(uintptr_t)1;
    size_t bytes = (uintptr_t)type61_steady_loop_end - begin;
    memcpy((void *)(type42_pages + 256), (const void *)begin, bytes);
    __dsb();
    __isb();
}
