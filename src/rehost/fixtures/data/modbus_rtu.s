; Synthetic Cortex-M fixture. Not a third-party firmware image.
; Assembled by rehost.fixtures for tests and `jig-emu run --fixture modbus-rtu`.
;
; Contract (see modbus_rtu.yaml):
;   UART 0x40000000  data +0, status +4, rx_irq 0
;   The reset handler enables IRQ 0 and executes WFI. When RX goes from
;   empty to non-empty the UART latches IRQ 0, the handler runs, and the
;   handler returns to BKPT.
;   The handler always consumes 8 request bytes (FC 0x03 and 0x06 are both
;   8 bytes on the wire). It does not check the request CRC.
;   Slave 1, FC 0x03, address 0, quantity 1:
;     response 01 03 02 12 34 plus CRC (holding register 0x1234).
;   Slave 1, FC 0x03, any other address: exception 01 83 02 plus CRC.
;   Slave 1, FC 0x03, address 0, quantity other than 1: exception 01 83 03 plus CRC.
;   Slave 1, any other function (including 0x06): exception with that
;     function's high bit set and code 01, plus CRC.
;   Any other slave: the 8 bytes are consumed and no response is sent.
;   Scratch in SRAM: request words at 0x20000000, length at 0x2000003C,
;   response body at 0x20000040.

        .thumb
        .syntax unified
        .cpu cortex-m3

        .word 0x20001000
        .thumb_word reset
        .word 0
        .word 0
        .word 0
        .word 0
        .word 0
        .word 0
        .word 0
        .word 0
        .word 0
        .word 0
        .word 0
        .word 0
        .word 0
        .word 0
        .thumb_word uart_rx

reset:
        movw r0, #0xe100
        movt r0, #0xe000
        movs r1, #1
        str  r1, [r0, #0]
        cpsie i
        wfi
        bkpt #0

uart_rx:
        movw r4, #0
        movt r4, #0x2000
        movw r5, #0
        movt r5, #0x4000
        ldr  r0, [r5, #0]
        str  r0, [r4, #0]
        ldr  r0, [r5, #0]
        str  r0, [r4, #4]
        ldr  r0, [r5, #0]
        str  r0, [r4, #8]
        ldr  r0, [r5, #0]
        str  r0, [r4, #12]
        ldr  r0, [r5, #0]
        str  r0, [r4, #16]
        ldr  r0, [r5, #0]
        str  r0, [r4, #20]
        ldr  r0, [r5, #0]
        str  r0, [r4, #24]
        ldr  r0, [r5, #0]
        str  r0, [r4, #28]
        ldr  r0, [r4, #0]
        cmp  r0, #1
        beq  slave_ok
        bx   lr
slave_ok:
        movw r3, #0x40
        movt r3, #0x2000
        movs r0, #1
        str  r0, [r3, #0]
        ldr  r0, [r4, #4]
        cmp  r0, #3
        beq  is_read
        movs r1, #0x80
        orrs r0, r1
        str  r0, [r3, #4]
        movs r0, #1
        str  r0, [r3, #8]
        movs r6, #3
        b    finish
is_read:
        ldr  r0, [r4, #8]
        cmp  r0, #0
        bne  bad_addr
        ldr  r0, [r4, #12]
        cmp  r0, #0
        bne  bad_addr
        ldr  r0, [r4, #16]
        cmp  r0, #0
        bne  bad_qty
        ldr  r0, [r4, #20]
        cmp  r0, #1
        bne  bad_qty
        movs r0, #3
        str  r0, [r3, #4]
        movs r0, #2
        str  r0, [r3, #8]
        movs r0, #0x12
        str  r0, [r3, #12]
        movs r0, #0x34
        str  r0, [r3, #16]
        movs r6, #5
        b    finish
bad_addr:
        movs r6, #2
        b    read_exc
bad_qty:
        movs r6, #3
read_exc:
        movs r0, #0x83
        str  r0, [r3, #4]
        str  r6, [r3, #8]
        movs r6, #3
finish:
        movw r1, #0x3c
        movt r1, #0x2000
        str  r6, [r1, #0]
        mov  r4, r3
        movw r2, #0xffff
        mov  r7, r6
crc_byte:
        cmp  r7, #0
        beq  crc_store
        ldr  r0, [r4, #0]
        eors r2, r0
        movs r6, #8
crc_bit:
        mov  r0, r2
        movs r1, #1
        ands r0, r1
        beq  crc_shift
        lsrs r2, r2, #1
        movw r0, #0xa001
        eors r2, r0
        b    crc_next
crc_shift:
        lsrs r2, r2, #1
crc_next:
        subs r6, #1
        bne  crc_bit
        adds r4, #4
        subs r7, #1
        b    crc_byte
crc_store:
        mov  r0, r2
        movs r1, #0xff
        ands r0, r1
        str  r0, [r4, #0]
        adds r4, #4
        lsrs r0, r2, #8
        str  r0, [r4, #0]
        movw r1, #0x3c
        movt r1, #0x2000
        ldr  r6, [r1, #0]
        adds r6, #2
tx_loop:
        ldr  r0, [r3, #0]
        str  r0, [r5, #0]
        adds r3, #4
        subs r6, #1
        bne  tx_loop
        bx   lr
