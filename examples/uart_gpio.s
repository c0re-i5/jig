; Synthetic Cortex-M Thumb-2 fixture. Not a third-party firmware image.
; Assembled by rehost.fixtures for tests and `rehost run --fixture uart-gpio`.
;
; Contract (see uart_gpio.yaml):
;   SRAM    0x20000000  +0 magic 0x00c0ffee, +4 SysTick VAL, +8 UART status
;   UART    0x40000000  data +0 gets 'A', status +4 has TX-empty bit 0x80
;   GPIO    0x40001000  ODR +0 written with 1
;   SysTick 0xE000E010  VAL +8 is read once
;   BKPT stops the run

        .thumb
        .syntax unified
        .cpu cortex-m3

        .word 0x20004000
        .thumb_word reset

reset:
        movw r4, #0
        movt r4, #0x2000
        movw r0, #0
        movt r0, #0x4000
        movs r1, #0x41
        str  r1, [r0, #0]
        movw r2, #0x1000
        movt r2, #0x4000
        movs r3, #1
        str  r3, [r2, #0]
        ldr  r1, [r0, #4]
        str  r1, [r4, #8]
        movw r5, #0xffee
        movt r5, #0x00c0
        str  r5, [r4, #0]
        movw r6, #0xe010
        movt r6, #0xe000
        ldr  r7, [r6, #8]
        str  r7, [r4, #4]
        bkpt #0
