; Synthetic Cortex-M fixture with a planted crash.
; The harness writes the testcase at 0x20000100 and zeroes the rest of the
; window. The first four bytes are compared with "JIG!" (0x4A, 0x49, 0x47,
; 0x21). Any other input executes BKPT. That exact sequence branches to an
; unmapped address and faults. Each matched byte falls through a compare, so
; the edge map grows one step at a time.

        .thumb
        .syntax unified

        .word 0x20001000
        .thumb_word start

start:
        movw r0, #0x0100
        movt r0, #0x2000
        ldrb r1, [r0, #0]
        cmp  r1, #0x4A
        bne  good
        ldrb r1, [r0, #1]
        cmp  r1, #0x49
        bne  good
        ldrb r1, [r0, #2]
        cmp  r1, #0x47
        bne  good
        ldrb r1, [r0, #3]
        cmp  r1, #0x21
        bne  good
        movw r2, #0x0001
        movt r2, #0x6000
        bx   r2
good:
        bkpt #0
