/* SPDX-License-Identifier: MIT
 * Read-only Flash MegaCart 4 MiB (CAR63), Atari800 DOC/cart.txt protocol.
 * Each bank has 17 prebiased pointers per 8 KiB half, including header seams.
 * The immutable map permits abandoned read-only fetches; only the final GPIO
 * guard authorizes output. FF polls control registers without serving ROM.
 * Preparation installs this loop before the launch ACK. Activation only
 * loads registers and switches SSI; it does not copy code after command FF.
 * Tables/code reuse the fixed cart_ram/type42_pages allocations.
 */
.syntax unified
.cpu cortex-m0plus
.thumb
.section .text.type63_bus_loop,"ax",%progbits
.global type63_bus_loop
.type type63_bus_loop, %function
.thumb_func
type63_bus_loop:
    ldr r3, =0x03a00000
    mov r11, r3
    mov r10, r1
#ifdef A8_TYPE61_LOOP
    movs r0, #0
#else
    movs r0, #254
#endif
    mov r12, r0
    lsls r0, r0, #2
    add r0, r10
    ldr r7, [r0]
    subs r7, #1
    mov r1, r7
    adds r1, #68
    mov r8, r1
    ldr r4, =0xd0000000
    ldr r5, =0x001fe000
    ldr r6, =0x03a01fff
    ldr r0, =0x0c000000
    mov r9, r0
    ldr r1, .Linitial_cached_value
    add r1, r10
    mov lr, r1
    mov r2, r10
    ldr r3, =(256 * 4 + 1)
    adds r2, r2, r3
    ldr r3, =type42_clock_start
    bx r3
    .balign 4
    .ltorg
 .balign 4
.Linitial_cached_value:
    .word 1025 + .Lcache_decode - .L63_copy_source
.size type63_bus_loop, .-type63_bus_loop

.section .text.type63_steady_loop,"ax",%progbits
    .balign 4
.L63_copy_source:
.global type63_steady_loop
.type type63_steady_loop, %function
.thumb_func
type63_steady_loop:
    mov r2, r8
    ldr r0, =0x18000000
    mov r8, r0
    movs r1, #0
    str r1, [r0, #8]
    ldr r1, =0x00470300
    str r1, [r0]
    movs r1, #0
    str r1, [r0, #4]
    movs r1, #1
    str r1, [r0, #8]
    dsb
    isb
    b .L63_current_poll
.L63_poll:
    ldr r0, [r4, #4]
.L63_decode:
    lsls r1, r0, #7
    bpl .L63_lower_selected
    bcc .L63_upper_selected
    lsls r1, r0, #10
    bmi .L63_poll
    b .L63_control
.L63_upper_selected:
    lsls r1, r0, #10
    bpl .L63_control
    lsls r1, r0, #8
    bpl .L63_release
.Lupper_fresh:
    nop
    nop
    nop
    nop
    mov r1, r11
    ldr r3, [r4, #4]
    eors r0, r3
    tst r0, r1
    bne .L63_current_poll
    /* Duplicate the small hot body so upper reads also fall through. */
.L63_upper_offset:
    lsls r0, r3, #19
    lsrs r0, r0, #19
    adds r0, #16
    lsrs r1, r0, #9
    lsls r1, r1, #2
    ldr r1, [r2, r1]
    lsls r0, r0, #8
    adds r0, r1
    mov r1, r8
    str r0, [r1, #96]
.Lupper_rx_wait:
    ldr r0, [r1, #40]
    lsls r0, r0, #28
    bpl .Lupper_rx_wait
    ldr r0, [r1, #96]
    uxtb r0, r0
.L63_upper_drive:
    ldr r1, [r4, #4]
    eors r1, r3
    tst r1, r6
    bne .Lupper_stale
    lsls r0, r0, #13
    add r0, r9
    str r0, [r4, #16]
    str r5, [r4, #36]
.L63_upper_hold:
    ldr r0, [r4, #4]
    eors r0, r3
    tst r0, r6
    beq .L63_upper_hold
    str r5, [r4, #40]
    mov r0, r3
    b .Lupper_fresh
.Lupper_stale:
    str r5, [r4, #40]
    ldr r1, =type42_stale_reads
    ldr r0, [r1]
    adds r0, #1
    str r0, [r1]
    b .L63_current_poll
.L63_lower_selected:
    lsls r1, r0, #10
    bpl .L63_control
    lsls r1, r0, #8
    bpl .L63_release
.Llower_fresh:
    nop
    nop
    nop
    nop
    mov r1, r11
    ldr r3, [r4, #4]
    eors r0, r3
    tst r0, r1
    bne .L63_current_poll
.L63_offset:
    lsls r0, r3, #19
    lsrs r0, r0, #19
    adds r0, #16
    lsrs r1, r0, #9
    lsls r1, r1, #2
    ldr r1, [r7, r1]
    lsls r0, r0, #8
    adds r0, r1
    mov r1, r8
    str r0, [r1, #96]
.Llower_rx_wait:
    ldr r0, [r1, #40]
    lsls r0, r0, #28
    bpl .Llower_rx_wait
    ldr r0, [r1, #96]
    uxtb r0, r0
.L63_drive:
    ldr r1, [r4, #4]
    eors r1, r3
    tst r1, r6
    bne .L63_stale
    lsls r0, r0, #13
    add r0, r9
    str r0, [r4, #16]
    str r5, [r4, #36]
.L63_hold:
    ldr r0, [r4, #4]
    eors r0, r3
    tst r0, r6
    beq .L63_hold
    str r5, [r4, #40]
    mov r0, r3
    b .Llower_fresh
.L63_release:
    str r5, [r4, #40]
.L63_current_poll:
    ldr r0, [r4, #4]
    bx lr
.L63_control:
    str r5, [r4, #40]
#ifdef A8_TYPE61_LOOP
    /* MegaMax latches address bits on either read or write. D5 reads never
     * drive data; the written data byte has no banking role. */
    lsls r1, r0, #9
    bpl .L63_current_poll
    mov r3, r0
.L61_control_high:
    ldr r0, [r4, #4]
    lsls r1, r0, #9
    bpl .L61_control_latch
    lsls r1, r0, #10
    bmi .L63_release
    mov r3, r0
    b .L61_control_high
.L61_control_latch:
    uxtb r0, r3
    movs r1, #128
    tst r0, r1
    bne .L63_disable
#else
    movs r1, #224
    tst r1, r0
    bne .L63_current_poll
    lsls r1, r0, #8
    bpl .L63_write
    mov r3, r0
    mov r0, r12
    b .L63_control_drive
.L63_write:
    lsls r1, r0, #9
    bpl .L63_current_poll
    mov r3, r0
.L63_write_high:
    ldr r0, [r4, #4]
    lsls r1, r0, #9
    bpl .L63_latch
    ldr r1, =0x00a000e0
    tst r1, r0
    bne .L63_release
    mov r3, r0
    b .L63_write_high
.L63_latch:
    lsrs r0, r3, #13
    uxtb r0, r0
    mov r12, r0
    cmp r0, #255
    beq .L63_disable
#endif
    lsls r1, r0, #2
    add r1, r10
    ldr r7, [r1]
    movs r1, #1
    tst r7, r1
    beq .L63_selected_flash
    subs r7, #1
    ldr r1, .L63_cached_value
    b .L63_selected_common
.L63_selected_flash:
    ldr r1, .L63_enabled_value
.L63_selected_common:
    add r1, r10
    mov lr, r1
    mov r1, r7
    adds r1, #68
    mov r2, r1
    ldr r0, =0x0c000000
    mov r9, r0
    str r0, [r4, #20]
    b .L63_current_poll
.L63_disable:
    ldr r0, =0x0c000000
    str r0, [r4, #24]
    movs r0, #0
    mov r9, r0
    ldr r1, .L63_disabled_value
    add r1, r10
    mov lr, r1
.L63_disabled_poll:
    ldr r0, [r4, #4]
.L63_disabled_decode:
    lsls r1, r0, #10
    bmi .L63_disabled_poll
    b .L63_control
.L63_control_drive:
    ldr r1, [r4, #4]
    eors r1, r3
    tst r1, r6
    bne .L63_stale
    lsls r0, r0, #13
    add r0, r9
    str r0, [r4, #16]
    str r5, [r4, #36]
.L63_control_hold:
    ldr r0, [r4, #4]
    eors r0, r3
    tst r0, r6
    beq .L63_control_hold
    str r5, [r4, #40]
    eors r0, r3
    bx lr
.L63_stale:
    str r5, [r4, #40]
    ldr r1, =type42_stale_reads
    ldr r0, [r1]
    adds r0, #1
    str r0, [r1]
    b .L63_current_poll
.Lcache_poll:
    ldr r0, [r4, #4]
.global type63_cached_decode
type63_cached_decode:
.Lcache_decode:
    lsls r1, r0, #7
    bpl .Lcache_lower_selected
    bcc .Lcache_upper_selected
    lsls r1, r0, #10
    bmi .Lcache_poll
    b .Lcache_control
.Lcache_upper_selected:
    lsls r1, r0, #10
    bpl .Lcache_control
    lsls r1, r0, #8
    bpl .Lcache_release
    mov r3, r0
    /* Duplicate the small hot body so upper reads also fall through. */
.Lcache_upper_offset:
    lsls r0, r0, #19
    lsrs r0, r0, #19
    adds r0, #16
    lsrs r1, r0, #9
    lsls r1, r1, #2
    ldr r1, [r2, r1]
    ldrb r0, [r1, r0]
.Lcache_upper_drive:
    ldr r1, [r4, #4]
    eors r1, r3
    tst r1, r6
    bne .Lcache_stale
    lsls r0, r0, #13
    add r0, r9
    str r0, [r4, #16]
    str r5, [r4, #36]
.Lcache_upper_hold:
    ldr r0, [r4, #4]
    eors r0, r3
    tst r0, r6
    beq .Lcache_upper_hold
    str r5, [r4, #40]
    eors r0, r3
    bx lr
.Lcache_lower_selected:
    lsls r1, r0, #10
    bpl .Lcache_control
    lsls r1, r0, #8
    bpl .Lcache_release
    mov r3, r0
.Lcache_offset:
    lsls r0, r0, #19
    lsrs r0, r0, #19
    adds r0, #16
    lsrs r1, r0, #9
    lsls r1, r1, #2
    ldr r1, [r7, r1]
    ldrb r0, [r1, r0]
.Lcache_drive:
    ldr r1, [r4, #4]
    eors r1, r3
    tst r1, r6
    bne .Lcache_stale
    lsls r0, r0, #13
    add r0, r9
    str r0, [r4, #16]
    str r5, [r4, #36]
.Lcache_hold:
    ldr r0, [r4, #4]
    eors r0, r3
    tst r0, r6
    beq .Lcache_hold
    str r5, [r4, #40]
    eors r0, r3
    bx lr
.Lcache_control:
    b .L63_control
.Lcache_release:
    str r5, [r4, #40]
    b .L63_current_poll
.Lcache_stale:
    b .L63_stale
    .balign 4
    .ltorg
.L63_cached_value:
    .word 1025 + .Lcache_decode - .L63_copy_source
.L63_enabled_value:
    .word 1025 + .L63_decode - .L63_copy_source
.L63_disabled_value:
    .word 1025 + .L63_disabled_decode - .L63_copy_source
.global type63_steady_loop_end
type63_steady_loop_end:
.size type63_steady_loop, .-type63_steady_loop
