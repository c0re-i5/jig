; Synthetic RV32I fixture. Not a third-party firmware image.
; Assembled by Jig for tests and `jig-emu run --fixture uart-gpio-rv32`.
;
; Contract (see uart_gpio_rv32.yaml). Boot sets sp and pc; there is no
; vector table. Instructions, in order:
;   lui, addi, sb, lui, addi, sw, lw, sw, lui, addi, sw, ebreak
;   SRAM    0x20000000  +0 magic 0x00c0ffee, +8 UART status
;   UART    0x40000000  data +0 gets 'A' (sb), status +4 is read (lw)
;   GPIO    0x40001000  ODR +0 written with 1 (sw)
;   ebreak  halts the run (the CpuBackend breakpoint, same as BKPT)

reset:
        lui     a0, 0x20000
        lui     a1, 0x40000
        addi    a2, zero, 0x41
        sb      a2, 0(a1)
        lui     a3, 0x40001
        addi    a4, zero, 1
        sw      a4, 0(a3)
        lw      a2, 4(a1)
        sw      a2, 8(a0)
        lui     a5, 0xc10
        addi    a5, a5, -18
        sw      a5, 0(a0)
        ebreak
