; Synthetic Cortex-M fixture for the fuzz-harness buffer sink.
; The harness writes the testcase at 0x20000100 before execution.
; This program loads that word and posts the low byte to UART, then BKPT.

        .thumb
        .syntax unified

        .word 0x20001000
        .thumb_word start

start:
        movw r0, #0x0100
        movt r0, #0x2000
        ldr  r1, [r0, #0]
        movw r2, #0
        movt r2, #0x4000
        str  r1, [r2, #0]
        bkpt #0
