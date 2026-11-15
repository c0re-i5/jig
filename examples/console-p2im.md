# P2IM Console (RIOT on FRDM-K64F)

`jig-emu run` on this map boots a second published Cortex-M image and
answers one RIOT shell command. The sample is P2IM Console: the RIOT
`examples/default` application built for the NXP FRDM-K64F (MK64FN1M0,
Cortex-M4). The precompiled ELF is
[`binary/Console`](https://github.com/RiS3-Lab/p2im-real_firmware/blob/master/binary/Console)
in [RiS3-Lab/p2im-real_firmware](https://github.com/RiS3-Lab/p2im-real_firmware).
The same target is in the
[Fuzzware P2IM Console experiment](https://github.com/fuzzware-fuzzer/fuzzware-experiments/tree/main/02-comparison-with-state-of-the-art/P2IM/Console).

This is not the P2IM CNC image. CNC is grbl on an STM32F407. Console is
RIOT on a Kinetis K64: flash at `0x00000000`, SRAM at `0x1FFF0000`, and a
byte-oriented UART0 instead of an STM32 USART.

This repository does not contain the ELF. CI does not run it. The session
below was run in a local VM against that ELF (15 Nov 2026). No test in
this tree checks those bytes.

The collection's
[LICENSE.md](https://github.com/RiS3-Lab/p2im-real_firmware/blob/master/LICENSE.md)
does not relicense the binaries. It points at each firmware's upstream
project. RIOT is LGPLv2.1. The image is a build of `examples/default` from
the 2018.04 line (the banner says `2018.04-vm-HEAD`). Keep your copy on
your machine. Read [RESPONSIBLE_USE.md](../RESPONSIBLE_USE.md).

## Map

[`console-p2im.yaml`](console-p2im.yaml) is a K64-shaped machine file:

- Flash is 1 MiB at `0x00000000`. SRAM is 256 KiB at `0x1FFF0000` (SRAM_L
  and SRAM_U are one contiguous block). Both Cortex-M bit-band windows are
  mapped. This image's `bit_set` / `bit_clear` helpers store through the
  peripheral alias.
- `mcg` is a `register_block`. `CLKST` copies `CLKS` until `PLLS` is set,
  and then reads as the PLL encoding (`3`). `PLLST` and `LOCK0` follow
  `PLLS`. `IREFST` follows `IREFS`. `OSCINIT0` follows `EREFS0`. That is
  the walk this startup polls. It is not a clock tree.
- `uart0` is the byte UART at `0x4006A000`. Status is `S1` at `+0x04`
  (`TDRE`/`TC` in `tx_empty_mask`, `RDRF` in `rx_ready_mask`). Data is `D`
  at `+0x07`. `rx_irq` is 31 (`UART0_RX_TX`). `rx_level: true` pends that
  line again while RX still holds bytes, because the RIOT handler reads
  one byte and returns.
- SIM, PORT, OSC, WDOG, SMC, and the other blocks in the bit-band target
  are sticky RAM windows. A store sticks, including a bit-band store. The
  bits are not decoded.
- `run.svc_nop` is `[63]`. P2IM images execute `svc #63` as `aflCall`. The
  collection's own note says QEMU intercepts that hook and does not change
  CPU state. Immediate 63 is retired as a NOP. `svc #1` is still the RIOT
  context switch.
- `timeout_ms: 0` and `max_instructions: 800000`. The shell does not halt.
  The cap stops the run after the banner and one `help`.

## Image

Pass the published ELF. Jig writes each `PT_LOAD` that has file bytes at
`p_paddr`. You do not run `objcopy` first.

| `p_paddr` | `p_vaddr` | `p_filesz` | What the loader writes |
| --- | --- | --- | --- |
| `0x00000000` | `0x00000000` | `0x400` | vectors |
| `0x00000400` | `0x00000400` | `0x10` | flash configuration field |
| `0x00000410` | `0x00000410` | `0x7850` | code and rodata, including the RIOT strings |
| `0x00007c60` | `0x1fff0200` | `0x150` | `.data` image in flash |

A fifth `PT_LOAD` is BSS at `0x1fff0000` with a file size of 0. It is not
written. SRAM starts zeroed, and startup clears BSS. The `.data` bytes stay
at `0x7c60` so the reset copy loop can move them to `0x1fff0200`. The
initial stack word is `0x1fff0200`.

```bash
curl -L -o Console \
  https://raw.githubusercontent.com/RiS3-Lab/p2im-real_firmware/master/binary/Console
```

A raw bin of those four spans, laid out from `0x00000000` with no gap,
still loads at `load.base`. The ELF is the file the recipe uses.

## Command session

`--serial-idle 8000` holds `help` until UART0 TX has been quiet for 8000
instructions, and it does not send the line until the banner has started.

```bash
jig-emu run -c examples/console-p2im.yaml -f Console \
  --serial-uart uart0 \
  --serial-idle 8000 \
  --serial-in 'help\n' \
  --snapshot-out console.snapshot.json
```

The recorded run exited 3: `status: instruction_limit`,
`detail: stopped after 800000 instructions`, `pc: 0x00000f88` (the shell
poll). The same command on another host can stop at a different PC inside
that poll. The TX text is the check.

```bash
python3 -c 'import json; tx=json.load(open("console.snapshot.json"))["peripherals"]["uart0"]["tx"]["__bytes__"]; print(bytes.fromhex(tx).decode())'
```

The captured text, in order:

```text
main(): This is RIOT! (Version: 2018.04-vm-HEAD)
Welcome to RIOT!
> help
Command              Description
---------------------------------------
reboot               Reboot the node
ps                   Prints information about running threads.
rtc                  control RTC peripheral interface
saul                 interact with sensors and actuators using SAUL
>
```

`help` is echoed and the four compiled commands are listed. The shell
prints another `>` and waits. `ps`, `rtc`, and `saul` were not sent in
that session. `saul` with no devices would print `No devices found` if the
command ran; that string is in the image and was not exercised. `reboot`
is a separate run, below.

The same exchange from Python:

```python
from pathlib import Path

from rehost.machine import Machine
from rehost.serial import run_lines

machine = Machine.from_path("examples/console-p2im.yaml")
machine.load_image(Path("Console").read_bytes())
result, tx, _new = run_lines(
    machine,
    ["help"],
    uart="uart0",
    idle_instructions=8000,
)
assert b"Welcome to RIOT!" in tx
assert b"reboot" in tx and b"Reboot the node" in tx
```

## Reboot

`reboot` writes `AIRCR.SYSRESETREQ`. The model treats that write, and
`VECTRESET`, as `boot(reset=True)`: SP and PC come back from the vector
table, the NVIC and the peripheral plugins return to the state from
construction, and the run continues. SRAM is not reloaded. RIOT's own
startup recopies `.data` and clears BSS. The UART `tx` buffer is kept, so
the snapshot still shows the first banner and the command. The RX queue
is dropped with the peripheral.

```bash
jig-emu run -c examples/console-p2im.yaml -f Console \
  --serial-uart uart0 \
  --serial-idle 8000 \
  --serial-in 'reboot\n' \
  --snapshot-out console-reboot.json
```

15 Nov 2026, the published Console ELF, the command above. Exit status 3:
`status: instruction_limit`, `resets: 1`, `pc: 0x00000f88` (the same shell
poll as the `help` session). The log line was
`core reset via AIRCR.SYSRESETREQ; reset 1, continuing at 0x0000099c`.

```text
main(): This is RIOT! (Version: 2018.04-vm-HEAD)
Welcome to RIOT!
> reboot
main(): This is RIOT! (Version: 2018.04-vm-HEAD)
Welcome to RIOT!
>
```

Both banners are in the 144-byte UART0 transcript. `run.halt_on_reset: true`
would have stopped on the write instead. `run.max_resets` (default 8)
stops a streak of resets that send no new UART byte, so a silent loop
cannot spend the 800000-instruction cap. This command printed, so that
cap did not apply. The run ended on the instruction cap, in the shell.

## What is still rough

- MCG timing is the follow rules above. There is no PLL lock delay and no
  K64 system clock. The shell still comes up.
- SIM, PORT, OSC, WDOG, SMC, and the other blocks in the RAM windows are
  not decoded. A store sticks. A bit the image expected to read back as a
  fixed reset value is whatever was written, or 0.
- UART `C2`, baud, and FIFO registers are logged and ignored. The stub
  reports `TDRE`/`TC` as set and `RDRF` from the queue.
- `rx_level` re-pends UART0 while bytes remain. The default UART latch is
  still one IRQ per burst. This image's handler reads a single byte, so
  the level flag is what lets `help` arrive whole.
- `svc #63` is a NOP because this P2IM build uses it as a fuzzer hook. A
  different image that uses immediate 63 as a real SVCall must drop it
  from `svc_nop`.
- The instruction cap ends the run in the shell poll. The shell does not
  halt. `reboot` does reset the core; the second banner is in the
  transcript above. `ps`, `rtc`, and `saul` are still unsent.
- There is no interactive TTY. `--serial-in` and `rehost.serial.run_lines`
  are the console. The fuzz path below queues bytes on UART0 RX after the
  banner.

## Fuzz campaign

`examples/console-p2im.yaml` uses the same UART sink as the CNC map.
UART0 RX, 64 bytes, checkpoint after TX contains `Welcome to RIOT` and has
been quiet for 8000 instructions. The case ends once RX is empty and TX
has been quiet for another 8000 instructions. A guest that never drains
RX runs to 120000 instructions, and that cap is not a hang.
`timeout_ms: 8000` is the hang. CI does not run this.

Seeds in [`examples/seeds/console/`](seeds/console/), each ending in a newline:

| File | Bytes |
| --- | --- |
| `00-empty.txt` | `\n` |
| `01-help.txt` | `help\n` |
| `02-ps.txt` | `ps\n` |
| `03-saul.txt` | `saul\n` |

`reboot` is not a seed. On this model it echoes the line and writes
`AIRCR.SYSRESETREQ`. The core resets and the banner is printed again, as
in the session above. A case that resets without sending any new UART
byte stops `halted` at `run.max_resets` (default 8). That stop is not a
crash. A case that prints the banner again is a normal execution and
keeps running until the idle gap or the instruction cap.

```bash
curl -L -o Console \
  https://raw.githubusercontent.com/RiS3-Lab/p2im-real_firmware/master/binary/Console

jig-emu fuzz -c examples/console-p2im.yaml -f Console \
  --out ./console-campaign \
  --seeds examples/seeds/console \
  --max-execs 1000 \
  --rng-seed 1
```

A banner checkpoint on the machine used for this note was 34159
instructions and under a second. TX was the `2018.04-vm-HEAD` line,
`Welcome to RIOT!`, and the `>` prompt. `help` from that snapshot printed
the four commands and returned to the prompt in about 33000 instructions.

### Recorded run

15 Nov 2026, in-process campaign, `--max-execs 1000 --rng-seed 1`,
against the published Console ELF (not stored in this tree):

```text
execs: 1000
corpus: 13
crashes: 0
buckets: 0
hangs: 0
edges: 1810
execs/sec: 4.7
seconds: 215.0
rng-seed: 1
```

The banner checkpoint before that timer was 34159 instructions, 0.77
seconds, PC `0x00000f88`, TX `main(): This is RIOT! (Version: 2018.04-vm-HEAD)`,
`Welcome to RIOT!`, and the `>` prompt. No fault and no hang in these
1000 executions. The corpus past the four seeds is shell editing
(`\x08` backspace, DEL) and a few one-byte edits of `help`. `reboot` was
not reached. The separate `reboot` probe above is the modeled reset, not
something this budget tripped.
