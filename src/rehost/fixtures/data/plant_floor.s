; Synthetic plant-floor controller. Not a third-party firmware image.
; Assembled by rehost.fixtures at base 0x08000000 for `jig-emu --fixture plant-floor`.
;
; The machine file is a small sibling of examples/stm32f4_clock.yaml:
;   flash   0x08000000   vector table and code
;   SRAM    0x20000000   tick word, scratch, fuzz buffer
;   GPIOA   0x40020000   ODR at offset 0x14 (run lamp, bit 0; tick lamp, bit 1)
;   USART2  0x40004400   status +0, data +4, rx_irq 38
;   RCC     0x40023800   CR.HSIRDY is stuck on
;   FLASH   0x40023C00   ACR is writable, SR.BSY reads as 0
;   SysTick 0xE000E010   one tick per instruction while ENABLE is set
;
; Boot polls those ready bits, lights GPIOA bit 0, and enables SysTick with
; TICKINT. The main loop does not continue until the tick word at 0x20000000
; is non-zero, which is the SysTick handler's store. LOAD is 0xFFFF, so the
; counter fires once (VAL starts at 0) and does not fire again during this
; program. The handler also sets GPIOA ODR bit 1.
;
; After that tick the reset handler enables IRQ 38. A Modbus RTU frame queued
; on USART2 before the run is already pending, so the handler runs before the
; next instruction. It consumes 8 request bytes and does not check the request
; CRC. Slave 1, function 0x03, address 0, quantity 1 answers with holding
; register 0x1234. Other reads and other function codes return an exception.
; Any other slave consumes the 8 bytes and sends nothing.
;
; The bytes that follow are a maintenance window the fuzzer feeds at
; 0x20000100. JIG! (4A 49 47 21) fetches unmapped 0x60000000. Any other input
; executes BKPT. That is the planted fault the short campaign buckets.

        .thumb
        .syntax unified
        .cpu cortex-m4

        .word 0x20004000
        .thumb_word reset
        .word 0                  ; NMI
        .word 0                  ; HardFault
        .zero 44                 ; MemManage .. PendSV (vector indexes 4..14)
        .thumb_word systick
        .zero 152                ; IRQ 0 .. IRQ 37
        .thumb_word usart2_rx

reset:
        movw r0, #0x3800
        movt r0, #0x4002
hsi:
        ldr  r1, [r0, #0]
        movs r2, #2
        ands r1, r2
        beq  hsi
        movw r0, #0x3c00
        movt r0, #0x4002
        movs r1, #2
        str  r1, [r0, #0]
flash_wait:
        ldr  r1, [r0, #12]
        cmp  r1, #0
        bne  flash_wait
        movw r0, #0x0000
        movt r0, #0x4002
        movs r1, #1
        str  r1, [r0, #0x14]
        movw r0, #0xe010
        movt r0, #0xe000
        movw r1, #0xffff
        str  r1, [r0, #4]
        str  r1, [r0, #8]
        movs r1, #7
        str  r1, [r0, #0]
        cpsie i
        movw r0, #0x0000
        movt r0, #0x2000
main_loop:
        ldr  r1, [r0, #0]
        cmp  r1, #0
        beq  main_loop
        movw r2, #0xe104
        movt r2, #0xe000
        movs r1, #0x40
        str  r1, [r2, #0]
maintenance:
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

systick:
        movw r0, #0x0000
        movt r0, #0x2000
        ldr  r1, [r0, #0]
        adds r1, #1
        str  r1, [r0, #0]
        movw r0, #0x0000
        movt r0, #0x4002
        ldr  r1, [r0, #0x14]
        movs r2, #2
        orrs r1, r2
        str  r1, [r0, #0x14]
        bx   lr

usart2_rx:
        movw r4, #0x0200
        movt r4, #0x2000
        movw r5, #0x4400
        movt r5, #0x4000
        ldr  r0, [r5, #4]
        str  r0, [r4, #0]
        ldr  r0, [r5, #4]
        str  r0, [r4, #4]
        ldr  r0, [r5, #4]
        str  r0, [r4, #8]
        ldr  r0, [r5, #4]
        str  r0, [r4, #12]
        ldr  r0, [r5, #4]
        str  r0, [r4, #16]
        ldr  r0, [r5, #4]
        str  r0, [r4, #20]
        ldr  r0, [r5, #4]
        str  r0, [r4, #24]
        ldr  r0, [r5, #4]
        str  r0, [r4, #28]
        ldr  r0, [r4, #0]
        cmp  r0, #1
        beq  slave_ok
        bx   lr
slave_ok:
        movw r3, #0x0240
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
        movw r1, #0x023c
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
        movw r1, #0x023c
        movt r1, #0x2000
        ldr  r6, [r1, #0]
        adds r6, #2
tx_loop:
        ldr  r0, [r3, #0]
        str  r0, [r5, #4]
        adds r3, #4
        subs r6, #1
        bne  tx_loop
        bx   lr
