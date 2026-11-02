/* v0.4: select-driven, SRAM-resident Type42 handler. No calls or flash-resident
 * instructions in the bus loop. Does not insert Atari wait states or patch ROM.
 * r7: zero = fragmented bank, otherwise direct ROM/cache pointer.
 * Disabled state uses impossible LR=FFFFFFFF; r7 may then also be zero.
 * Control writes/reads both latch the ADDRESS; D580-D5FF disables RD5.
 */
.syntax unified
.cpu cortex-m0plus
.thumb
.section .time_critical.type42_bus_loop,"ax",%progbits
.global type42_bus_loop
.type type42_bus_loop, %function
.thumb_func
type42_bus_loop:
    mov r11, r0                 /* all file-page pointers */
    mov r10, r1                 /* direct-bank pointer table */
    ldr r2, =type42_initial_bank
    ldr r2, [r2]               /* Type42: 127; J(atari)Cart: zero */
    lsls r3, r2, #6
    adds r0, r0, r3
    mov r8, r0                  /* active bank's page pointers */
    lsls r2, r2, #2
    ldr r7, [r1, r2]
    ldr r4, =0xd0000000         /* SIO */
    ldr r5, =0x001fe000         /* data GPIO mask */
    ldr r6, =0x02a01fff         /* address + S5/RW/CCTL validity mask */
    ldr r0, =0x08000000         /* RD5 */
    mov r9, r0
    ldr r0, =0x02a00000         /* S5 | R/W | CCTL */
    mov r12, r0
    ldr r0, =0x00a00000         /* read = S5 low, R/W and CCTL high */
    mov lr, r0

.Lpoll:
    ldr r0, [r4, #4]
.Ldecode:
    /* Disabled LR=FFFFFFFF cannot equal any r12-masked GPIO value. */
    mov r1, r12
    ands r1, r0
    cmp r1, lr
    bne .Lcontrol_or_idle
    /* Like upstream's standard-8K handler, begin on S5, before PHI2 high
     * when select/address are already valid. Never wait for the clock to
     * begin a cold flash fetch. Entry/hold/stale/control predecessors leave
     * data OE clear before reaching a new fetch. */
    mov r3, r0
    lsls r0, r0, #19
    lsrs r0, r0, #19            /* low 13 address bits */
    movs r1, r7
    bne .Lfetch
    adds r0, #16               /* preserve CAR-header displacement */
    lsrs r1, r0, #9
    lsls r1, r1, #2
    mov r2, r8
    ldr r1, [r2, r1]
    lsls r0, r0, #23
    lsrs r0, r0, #23
.Lfetch:
    ldr r2, [r4, #4]
    eors r2, r3
    tst r2, r6
    bne .Lpoll
    ldrb r0, [r1, r0]

.Ldrive:
    ldr r1, [r4, #4]
    eors r1, r3
    tst r1, r6
    bne .Lstale                 /* don't drive a byte for an obsolete request */
    lsls r0, r0, #13
    add r0, r9                 /* disjoint shifted byte + constant RD5 */
    str r0, [r4, #16]           /* data latches and RD5 */
    str r5, [r4, #36]           /* data output enable */
.Lhold:
    ldr r0, [r4, #4]
    eors r0, r3
    tst r0, r6
    beq .Lhold                  /* keep output while address/select stay valid */
    str r5, [r4, #40]           /* release before restoring successor GPIO */
    eors r0, r3
    b .Ldecode
.Lcontrol_or_idle:
    lsls r1, r0, #10           /* CCTL bit 21 into sign */
    bmi .Lpoll                 /* not a D5xx access */
    lsls r1, r0, #9            /* latch D5xx only while PHI2 high */
    bpl .Lpoll
    lsls r1, r0, #24           /* low-address bit 7 disables */
    bmi .Ldisable
    ldr r1, =type42_bank_mask
    ldr r1, [r1]               /* 127 / 31 / 63 for standard 42 / 109 / 110 */
    ands r0, r1
    lsls r1, r0, #6
    add r1, r11
    mov r8, r1
    lsls r0, r0, #2
    mov r1, r10
    ldr r7, [r1, r0]
.Lenable:
    mov r0, r9
    str r0, [r4, #20]
    ldr r0, =0x00a00000
    mov lr, r0                 /* enabled read decode expectation */
    b .Lcontrol_end
.Ldisable:
    movs r7, #0
    mov r0, r9
    str r0, [r4, #24]
    mvns r0, r7                /* r7 is zero: impossible masked expectation */
    mov lr, r0
.Lcontrol_end:
    ldr r0, [r4, #4]
    lsls r1, r0, #9
    bmi .Lcontrol_end
    b .Ldecode
.Lstale:
    ldr r1, =type42_stale_reads
    ldr r0, [r1]
    adds r0, #1
    str r0, [r1]
    b .Lpoll
    .balign 4
    .ltorg
    .space 244-(.-type42_bus_loop), 0
.size type42_bus_loop, .-type42_bus_loop


/* DCart (CAR112) keeps the immutable file-page/direct-bank tables. Its last
 * 16 KiB of cart_ram contain 64 immutable 256-byte B500-B5FF mirrors.
 * Only D5 writes latch the address. D5 reads always mirror the selected
 * bank's B500-B5FF bytes, including while RD5 is disabled. No ROM writes,
 * file operations, demand loading, or changes to the Type42 loop above.
 * r7 retains the selected bank pointer (1 = fragmented), even when off.
 * r9 is the current RD5 output bit; reads preserve it without re-enabling.
 */
.section .text.dcart_bus_loop,"ax",%progbits
.global dcart_bus_loop
.type dcart_bus_loop, %function
.thumb_func
dcart_bus_loop:
    mov r11, r0                 /* all file-page pointers */
    mov r10, r1                 /* direct-bank pointer table */
    /* CAR112 uses 1025 of the existing 2049 file-page entries. Its inactive
     * table tail holds the code and literal pool, just as CAR30 does below.
     * Copy at the normal menu divider before the SRAM-only SSI transition.
     * Every subsequent image admission clears the complete pointer table. */
    ldr r3, =(1025 * 4)
    adds r2, r0, r3
    ldr r1, =.Ldcart_copy_source
    ldr r3, =dcart_steady_loop_end
    subs r3, r3, r1
.Ldcart_copy:
    ldr r0, [r1]
    str r0, [r2]
    adds r1, #4
    adds r2, #4
    subs r3, #4
    bne .Ldcart_copy
    mov r8, r11                /* DCart powers up in bank zero */
    mov r1, r10
    ldr r7, [r1]
    cmp r7, #0
    bne 1f
    movs r7, #1
1:
    ldr r4, =0xd0000000
    ldr r5, =0x001fe000         /* data GPIO mask */
    ldr r6, =0x02a01fff         /* S5 default; D5 restores before leaving */
    ldr r0, =0x08000000
    mov r9, r0                  /* RD5 starts enabled */
    ldr r0, =0x02a00000
    mov r12, r0
    ldr r0, =0x00a00000         /* S5 low, R/W and CCTL high */
    mov lr, r0
    mov r2, r11
    ldr r3, =(1025 * 4 + 1)     /* copied loop's SRAM address + Thumb bit */
    adds r2, r2, r3
    ldr r3, =type42_clock_start
    bx r3                     /* switch SSI only after reaching SRAM */
    .balign 4
    .ltorg
.size dcart_bus_loop, .-dcart_bus_loop

/* Keep one-time GPIO/register setup in flash at the menu divider. This common
 * SRAM handoff changes SSI using only r0/r1/r3, preserves the selected DCart
 * registers and destination r2, then transfers directly into a SRAM loop.
 * No stack, calls, flash instructions or flash literals after SSI is stopped. */
.section .text.type42_start_bus,"ax",%progbits
.global type42_start_bus
.type type42_start_bus, %function
.thumb_func
type42_start_bus:
    ldr r2, =type42_bus_loop
    ldr r3, =type42_clock_start
    bx r3
    .balign 4
    .ltorg
.size type42_start_bus, .-type42_start_bus

#ifndef A8_TYPE42_FLASH_DIVIDER
#define A8_TYPE42_FLASH_DIVIDER 2
#endif
#if A8_TYPE42_FLASH_DIVIDER != 2 && A8_TYPE42_FLASH_DIVIDER != 4
#error A8_TYPE42_FLASH_DIVIDER must be 2 or 4
#endif
.section .time_critical.type42_clock_start,"ax",%progbits
.global type42_clock_start
.type type42_clock_start, %function
.thumb_func
type42_clock_start:
    ldr r3, =0x18000000         /* SSI registers */
    movs r0, #1
3:
    ldr r1, [r3, #40]
    tst r1, r0                /* wait until SSI is idle */
    bne 3b
    movs r1, #0
    str r1, [r3, #8]
    movs r1, #A8_TYPE42_FLASH_DIVIDER
    str r1, [r3, #20]
    str r0, [r3, #8]
    dsb
    isb
    ldr r0, =type42_pages
    ldr r1, =type42_bank_base
    bx r2
    .balign 4
    .ltorg
.size type42_clock_start, .-type42_clock_start

.section .text.dcart_steady_loop,"ax",%progbits
    .balign 4
.Ldcart_copy_source:
.global dcart_steady_loop
.type dcart_steady_loop, %function
.thumb_func
dcart_steady_loop:

.Ldcart_poll:
    ldr r0, [r4, #4]
.Ldcart_decode:
    mov r1, r12
    ands r1, r0
    cmp r1, lr
    bne .Ldcart_control_or_idle
    mov r3, r0
    lsls r0, r0, #19
    lsrs r0, r0, #19           /* low 13 ROM address bits */

.Ldcart_fetch:
    cmp r7, #1
    bne .Ldcart_direct
    adds r0, #16               /* CAR-header displacement is retained */
    lsrs r1, r0, #9
    lsls r1, r1, #2
    mov r2, r8
    ldr r1, [r2, r1]
    lsls r0, r0, #23
    lsrs r0, r0, #23
    ldr r2, [r4, #4]
    eors r2, r3
    tst r2, r6
    bne .Ldcart_poll
    ldrb r0, [r1, r0]

.Ldcart_drive:
    ldr r1, [r4, #4]
    eors r1, r3
    tst r1, r6
    bne .Ldcart_stale
    lsls r0, r0, #13
    mov r1, r9
    orrs r0, r1                /* preserve RD5, including its disabled state */
    str r0, [r4, #16]
    str r5, [r4, #36]
.Ldcart_hold:
    ldr r0, [r4, #4]
    mov r1, r0
    eors r1, r3
    tst r1, r6
    beq .Ldcart_hold
    str r5, [r4, #40]          /* release before mask restore or decode */
    ldr r6, =0x02a01fff
    b .Ldcart_decode
.Ldcart_direct:
    /* As with Type42, publish only after validating the completed fetch. */
    ldr r2, [r4, #4]
    eors r2, r3
    tst r2, r6
    bne .Ldcart_poll
    ldrb r0, [r7, r0]
    b .Ldcart_drive
.Ldcart_d5_read:
    /* A D5 read is not a control access. Keep bank and RD5 unchanged. */
    lsls r1, r0, #9
    bpl .Ldcart_poll           /* D5 data only drives during PHI2 high */
    ldr r6, =0x02e01fff         /* D5 fetch/hold also validates PHI2 */
    mov r3, r0
    lsls r0, r0, #24
    lsrs r0, r0, #24
    /* Resolve the already selected bank without changing RD5 or bank state.
     * Each bank occupies 64 bytes of the file-page pointer table, so the
     * table displacement times four is its 256-byte mirror displacement. */
    mov r2, r8
    mov r1, r11
    subs r2, r2, r1
    lsls r2, r2, #2
    ldr r1, =(cart_ram + 112 * 1024)
    adds r2, r2, r1
    ldrb r0, [r2, r0]          /* D5 reads are always SRAM, even with RD5 off */
    b .Ldcart_drive
.Ldcart_control_or_idle:
    str r5, [r4, #40]
    lsls r1, r0, #10           /* CCTL bit 21 into sign */
    bmi .Ldcart_poll
    lsls r1, r0, #8            /* R/W bit 23: read returns the mirror */
    bmi .Ldcart_d5_read
    lsls r1, r0, #9            /* latch writes only while PHI2 high */
    bpl .Ldcart_poll
    movs r1, #63
    ands r1, r0                /* data is ignored; address low six selects bank */
    lsls r2, r1, #6
    add r2, r11
    mov r8, r2
    lsls r1, r1, #2
    mov r2, r10
    ldr r7, [r2, r1]
    cmp r7, #0
    bne 2f
    movs r7, #1
2:
    lsls r1, r0, #24           /* bit 7 of write address disables RD5 */
    bmi .Ldcart_disable
    ldr r0, =0x08000000
    mov r9, r0
    str r0, [r4, #20]
    movs r0, #0xa0
    lsls r0, r0, #16
    mov lr, r0                 /* enabled decode expected=00A00000 */
    b .Ldcart_control_end
.Ldcart_disable:
    ldr r0, =0x08000000
    str r0, [r4, #24]
    movs r0, #0
    mov r9, r0
    mvns r0, r0
    mov lr, r0                 /* disabled impossible expected=FFFFFFFF */
.Ldcart_control_end:
    ldr r0, [r4, #4]
    lsls r1, r0, #9
    bmi .Ldcart_control_end
    b .Ldcart_decode
.Ldcart_stale:
    str r5, [r4, #40]
    ldr r6, =0x02a01fff         /* D5 stale path cannot leak its PHI mask */
    ldr r1, =type42_stale_reads
    ldr r0, [r1]
    adds r0, #1
    str r0, [r1]
    b .Ldcart_poll
    .balign 4
    .ltorg
.global dcart_steady_loop_end
dcart_steady_loop_end:
.size dcart_steady_loop, .-dcart_steady_loop

/* MegaCart256 (CAR30) presents two adjacent 8 KiB halves at $8000-$BFFF.
 * A D5 write latches its DATA at falling PHI2: low nibble selects a 16 KiB
 * bank, bit 7 disables both cartridge windows. D5 reads never drive or latch.
 * Existing immutable page/base tables remain in 8 KiB units. r7 points to
 * the selected bank's pair of base entries; r8 to its first page entry.
 */
.section .text.megacart_bus_loop,"ax",%progbits
.global megacart_bus_loop
.type megacart_bus_loop, %function
.thumb_func
megacart_bus_loop:
    mov r11, r0
    mov r10, r1
    /* CAR30 needs only 513 of the existing 2049 file-page entries. Reuse
     * its inactive table tail for code instead of increasing fixed SRAM.
     * Copy code plus its internal literal pool before changing SSI. The
     * loader clears this whole table before every mapper admission. */
    ldr r3, =(513 * 4)
    adds r2, r0, r3
    ldr r1, =.Lmega_copy_source
    ldr r3, =megacart_steady_loop_end
    subs r3, r3, r1
.Lmega_copy:
    ldr r0, [r1]
    str r0, [r2]
    adds r1, #4
    adds r2, #4
    subs r3, #4
    bne .Lmega_copy
    mov r8, r11                /* power up in 16 KiB bank zero */
    mov r7, r10
    ldr r4, =0xd0000000
    ldr r5, =0x001fe000
    ldr r6, =0x03a01fff        /* both selects, R/W, CCTL and address */
    ldr r0, =0x0c000000
    mov r9, r0                 /* RD4 and RD5 start enabled */
    ldr r0, =0x00a00000
    mov r12, r0                /* CCTL and R/W */
    ldr r0, =0x03000000
    mov lr, r0                 /* S4 and S5 */
    mov r2, r11
    ldr r3, =(513 * 4 + 1)      /* copied loop's SRAM address + Thumb bit */
    adds r2, r2, r3
    ldr r3, =type42_clock_start
    bx r3
    .balign 4
    .ltorg
.size megacart_bus_loop, .-megacart_bus_loop

.section .text.megacart_steady_loop,"ax",%progbits
    .balign 4
.Lmega_copy_source:
.global megacart_steady_loop
.type megacart_steady_loop, %function
.thumb_func
megacart_steady_loop:
.Lmega_poll:
    ldr r0, [r4, #4]
.Lmega_decode:
    mov r1, r12
    ands r1, r0
    cmp r1, r12
    bne .Lmega_control_or_idle
    mov r1, lr
    ands r1, r0
    cmp r1, lr
    beq .Lmega_release          /* neither ROM window selected */
    mov r1, r9
    cmp r1, #0
    beq .Lmega_release
    str r5, [r4, #40]
    mov r3, r0
    lsls r1, r0, #7            /* S4 high selects the upper 8 KiB half */
    bmi .Lmega_upper
    mov r1, r8
    mov r2, r7
    ldr r2, [r2]
    b .Lmega_selected
.Lmega_upper:
    mov r1, r8
    adds r1, #64               /* 16 file-page entries per 8 KiB half */
    mov r2, r7
    ldr r2, [r2, #4]
.Lmega_selected:
    lsls r0, r0, #19
    lsrs r0, r0, #19
    cmp r2, #0
    beq .Lmega_fragmented
    ldr r1, [r4, #4]
    eors r1, r3
    tst r1, r6
    bne .Lmega_poll
    ldrb r0, [r2, r0]
    b .Lmega_drive
.Lmega_fragmented:
    adds r0, #16               /* retain the CAR header displacement */
    lsrs r2, r0, #9
    lsls r2, r2, #2
    ldr r2, [r1, r2]
    lsls r0, r0, #23
    lsrs r0, r0, #23
    ldr r1, [r4, #4]
    eors r1, r3
    tst r1, r6
    bne .Lmega_poll
    ldrb r0, [r2, r0]
.Lmega_drive:
    ldr r1, [r4, #4]
    eors r1, r3
    tst r1, r6
    bne .Lmega_stale
    lsls r0, r0, #13
    mov r1, r9
    orrs r0, r1
    str r0, [r4, #16]
    str r5, [r4, #36]
.Lmega_hold:
    ldr r0, [r4, #4]
    mov r1, r0
    eors r1, r3
    tst r1, r6
    beq .Lmega_hold
    b .Lmega_decode
.Lmega_release:
    str r5, [r4, #40]
    b .Lmega_poll
.Lmega_control_or_idle:
    str r5, [r4, #40]
    lsls r1, r0, #10           /* CCTL must be low */
    bmi .Lmega_poll
    lsls r1, r0, #8            /* D5 reads leave state and bus unchanged */
    bmi .Lmega_poll
    lsls r1, r0, #9
    bpl .Lmega_poll
    mov r3, r0
.Lmega_write_high:
    ldr r0, [r4, #4]
    lsls r1, r0, #9
    bpl .Lmega_latch
    mov r1, r12
    tst r1, r0                 /* abandon a write deselected before falling PHI2 */
    bne .Lmega_release
    mov r3, r0                 /* data may settle late in PHI2 high */
    b .Lmega_write_high
.Lmega_latch:
    lsrs r0, r3, #13
    movs r1, #15
    ands r0, r1
    lsls r1, r0, #7
    add r1, r11
    mov r8, r1
    lsls r0, r0, #3
    add r0, r10
    mov r7, r0
    ldr r0, =0x0c000000
    lsls r1, r3, #11           /* written data bit 7 disables both windows */
    bmi .Lmega_disable
    mov r9, r0
    str r0, [r4, #20]
    b .Lmega_control_end
.Lmega_disable:
    str r0, [r4, #24]
    movs r0, #0
    mov r9, r0
.Lmega_control_end:
    ldr r0, [r4, #4]
    b .Lmega_decode
.Lmega_stale:
    str r5, [r4, #40]
    ldr r1, =type42_stale_reads
    ldr r0, [r1]
    adds r0, #1
    str r0, [r1]
    b .Lmega_poll
    .balign 4
    .ltorg
.Lmega_steady_end:
.global megacart_steady_loop_end
megacart_steady_loop_end:
.size megacart_steady_loop, .-megacart_steady_loop
