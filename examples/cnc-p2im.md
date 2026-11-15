# P2IM CNC (grbl 0.8c) on jig-emu

`jig-emu run` on the STM32F4 map boots a published Cortex-M image and then
exchanges a short Grbl session on USART2. The sample is P2IM CNC: grbl 0.8c
on an STM32F407VG. The precompiled ELF is
[`binary/CNC`](https://github.com/RiS3-Lab/p2im-real_firmware/blob/master/binary/CNC)
in [RiS3-Lab/p2im-real_firmware](https://github.com/RiS3-Lab/p2im-real_firmware).
The same target is written up with a map in the
[Fuzzware P2IM CNC experiment](https://github.com/fuzzware-fuzzer/fuzzware-experiments/tree/main/02-comparison-with-state-of-the-art/P2IM/CNC).

This repository does not contain the ELF or the raw bin. CI executes the
synthetic `plant-floor` fixture and the serial-injection unit tests. The
session below was run in a local VM against that ELF (15 Nov 2026). No test
in this tree checks those bytes.

The collection's
[LICENSE.md](https://github.com/RiS3-Lab/p2im-real_firmware/blob/master/LICENSE.md)
does not relicense the binaries. It points at each firmware's upstream
project. Grbl is GPLv3. Keep your copy on your machine. Read
[RESPONSIBLE_USE.md](../RESPONSIBLE_USE.md). Other images in that collection
are outside this note.

## Map

[`cnc-p2im.yaml`](cnc-p2im.yaml) starts from
[`stm32f4_clock.yaml`](stm32f4_clock.yaml). RCC `follow` and both bit-band
windows are the template's. The CNC file adds:

- `tim2` as the `timer` plugin, IRQ 28, `tick_every: 1500`. That is one
  update event per 1500 retired instructions while CR1.CEN is set. Compare
  flags are raised when CCR1 or CCR2 is non-zero, which is how this image
  arms the step pulse. The next event waits until the handler clears the
  enabled status bits. ARR is a latch. It does not pace the event.
- GPIO A through E as `gpio` plugins with `idr_offset: 0x10`,
  `odr_offset: 0x14`, `bsrr_offset: 0x18`, and `idr: 0xFFFF`. A 1 in the low
  half of BSRR sets ODR. A 1 in the high half clears it. IDR reads high so
  idle-high inputs look released.
- `timeout_ms: 0` and `max_instructions: 2400000`. The protocol loop does
  not halt. The cap stops the run after the session.

USART2 is the byte UART at `0x40004400` (status +0, data +4, `rx_irq: 38`).
This image polls `usart_tstc` / `usart_getc`. It does not enable the USART2
NVIC line. The weak `USART2_IRQHandler` is a spin, so leave that line
disabled.

## What the image actually waits on

After the banner the CPU sits in `serial_read` (`0x08008287`), which calls
`usart_tstc` and returns `0xff` while RXNE is clear. Commands are ordinary
USART2 bytes. `?` is handled in `serial_rx_hook` and does not enter the
line buffer.

The step generator is TIM2. `TIM2_IRQHandler` (`0x08007c7d`) checks SR/DIER
bits 1, 2, and 0 (CC1, CC2, update) and calls `step_delay_isr`,
`step_pulse_isr`, and `step_period_isr`. `step_isr_enable` sets CR1.CEN and
DIER.UIE, plus the compare enables when CCR1/CCR2 are non-zero. Step and
direction pins are GPIOE ODR (`0x40021000`) via a read-modify-write in
`step_wr`, not BSRR. `gpio_set` / `gpio_clr` and `HAL_GPIO_WritePin` do use
BSRR halfword stores. Both paths are covered by the gpio plugin.

`eeprom_get_char` / `eeprom_put_char` are a 1 KiB RAM buffer at
`0x20000470`. `eeprom_init` fills four bytes with `0xFF`. The checksum fails,
Grbl prints `error: EEPROM read fail. Using defaults`, and then writes the
compiled defaults into that buffer. There is no flash-backed EEPROM model
because this image does not program one. A later `$0=100` in the same run
reads back as `$0=100.000`. A new process prints the failure again.

TIM4 at `0x40000800` is the g540 timer. `timers_init` starts it with CEN set
and DIER clear. Nothing in the command session waits on it. The window is
still unmapped. PWR, SYSCFG, and EXTI are `unimplemented` and are touched
during init only.

## Image

Pass the published ELF. Jig writes each `PT_LOAD` that has file bytes at
`p_paddr`. You do not run `objcopy` first. A rebuild from the `CNC/`
sources in that repository is a different image.

| `p_paddr` | `p_vaddr` | `p_filesz` | What the loader writes |
| --- | --- | --- | --- |
| `0x08000000` | `0x08000000` | `0xc0c0` | vectors, code, rodata, at `0x08000000` |
| `0x0800c0c0` | `0x20000000` | `0x44c` | `.data` image, at `0x0800c0c0` in flash |

The `p_vaddr` of the second segment is SRAM. Writing the bytes there would
skip the address the reset handler copies from. A third `PT_LOAD` is BSS at
`0x2000044c` with a file size of 0. It is not written. Reset copies `.data`
and clears BSS. The first word stays `0x2001FFFF` (Atollic `_estack`, odd).
Leave it odd. The CPU model clears SP[1:0].

A raw bin of those two spans, laid out from `0x08000000` with no gap, is
50444 bytes and still loads at `load.base`. The ELF is the file the recipe
uses. Intel HEX of the same spans loads too. The recorded ELF session and a
HEX boot both reached the Grbl banner. The full command below was the ELF.

## Command session

`--serial-idle 8000` holds each line until USART2 TX has been quiet for 8000
instructions, and it does not send the first line until the banner has
started. `--serial-settle 700000` waits that many extra instructions before
the last `?`, so the step ISR can finish. Without the settle, a `?` typed in
the next quiet gap often still sees `<Run,MPos:0.000,...>` because Grbl
prints `ok` when the block is planned, and the steps happen afterward.

```bash
jig-emu run -c examples/cnc-p2im.yaml -f CNC \
  --serial-uart usart2 \
  --serial-idle 8000 \
  --serial-settle 700000 \
  --serial-in '$$\n' \
  --serial-in '?\n' \
  --serial-in '$X\n' \
  --serial-in 'G91 G0 X1\n' \
  --serial-in '?\n' \
  --snapshot-out cnc.snapshot.json
```

The recorded run exited 3: `status: instruction_limit`,
`detail: stopped after 2400000 instructions`, `pc: 0x08007e66` (inside
`usart_tstc`), `sp: 0x2001ffbc`, SysTick `ctrl: 0x7` `load: 0x2903f`,
`tim2 cr: 0x0 dier: 0x0 sr: 0x0 events: 158`. GPIOE `odr` was `0xa80`.
The same command on another host can stop at a different PC inside the
poll. The TX text and the timer having stopped are the check.

```bash
python3 -c 'import json; tx=json.load(open("cnc.snapshot.json"))["peripherals"]["usart2"]["tx"]["__bytes__"]; print(bytes.fromhex(tx).decode())'
```

Key replies from that capture, in order:

```text
error: EEPROM read fail. Using defaults
...
Grbl 0.8c ['$' for help]
['$H'|'$X' to unlock]
$0=157.480 (x, step/mm)
...
ok
<Alarm,MPos:0.000,0.000,0.000,WPos:0.000,0.000,0.000>
ok
[Caution: Unlocked]
ok
ok
<Idle,MPos:0.997,0.000,0.000,WPos:0.997,0.000,0.000>
ok
```

`$$` repeats the compiled settings and ends with `ok`. The first `?` is the
alarm lock from `$17=1` (homing cycle), not from a limit pin. `$X` prints
`[Caution: Unlocked]` and `ok`. `G91 G0 X1` prints `ok`. The settled `?`
prints Idle at X `0.997`. That is 157 steps divided by 157.480 steps/mm,
shown to three decimals. TIM2 had delivered 158 update events and the
firmware had cleared CEN.

A separate pass in the same VM sent `$0=100` and then `$$`. The second
listing showed `$0=100.000`. That write lives in the RAM EEPROM buffer for
the rest of the process.

The same exchange from Python:

```python
from rehost.machine import Machine
from rehost.serial import run_lines

machine = Machine.from_path("examples/cnc-p2im.yaml")
machine.load_image(open("CNC", "rb").read())
result, tx, _new = run_lines(
    machine,
    ["$$", "?", "$X", "G91 G0 X1", "?"],
    uart="usart2",
    idle_instructions=8000,
    settle_before=[0, 0, 0, 0, 700000],
)
assert b"<Idle,MPos:0.997," in tx
```

## What is still rough

- The timer counts instructions, not the STM32 prescaler. Pulse width and
  step rate are not the microseconds in `$3`. The move still completes.
- TIM4 (g540) is unmapped. The session did not need it.
- Cold boot still reports `EEPROM read fail`. Nothing restores the RAM
  buffer from flash.
- PWR, SYSCFG, and EXTI stay `unimplemented`. Init touches them and moves on.
- USART CR, BRR, and GTPR writes are logged and ignored. The stub is always
  ready to transmit and reports RXNE from the queue.
- A cap of 3000000 on this command entered `main` again and printed a second
  `Grbl 0.8c` banner. 2400000 stops in the poll after the Idle line. The
  step timer had already gone idle; that later re-entry is not the move.
- There is no interactive TTY. `--serial-in` and `rehost.serial.run_lines`
  are the console. The fuzz path below queues bytes on USART2 RX after the
  banner, instead of writing a RAM buffer.

## Fuzz campaign

`examples/cnc-p2im.yaml` has a `fuzz:` section. The sink is USART2 RX, up
to 64 bytes. `jig-emu fuzz` boots, waits until TX contains `Grbl 0.8c` and
has then been quiet for 8000 instructions, and snapshots that state. Each
case restores the snapshot and queues the testcase. The case ends once RX
is empty and TX has been quiet for 8000 instructions. That covers a reply
and also a partial line Grbl is holding with no newline. A guest that
never drains RX runs to 120000 instructions. That cap is a finished
execution (`hang_on_limit: false`). `timeout_ms: 8000` is the hang. CI
does not download the ELF and does not start this run.

The seeds are text files under [`examples/seeds/cnc/`](seeds/cnc/). Each
one ends in a newline:

| File | Bytes |
| --- | --- |
| `00-empty.txt` | `\n` |
| `01-status.txt` | `?\n` |
| `02-help.txt` | `$\n` |
| `03-unlock.txt` | `$X\n` |
| `04-settings.txt` | `$$\n` |
| `05-motion.txt` | `G91\n` |

Names sort in that order, which is the order the deterministic byte walk
uses. `G91` is the motion parser while the alarm lock is still on. A long
`G0` is not a seed: the step ISR keeps going after `ok`, and this budget
is sized for a line, not for a move.

```bash
curl -L -o CNC \
  https://raw.githubusercontent.com/RiS3-Lab/p2im-real_firmware/master/binary/CNC

jig-emu fuzz -c examples/cnc-p2im.yaml -f CNC \
  --out ./cnc-campaign \
  --seeds examples/seeds/cnc \
  --max-execs 3000 \
  --rng-seed 1
```

`--rng-seed 1` makes the havoc stage repeatable after the deterministic
walk. The walk itself does not use the RNG. The same harness under
afl-fuzz, with `-t` large enough for the one-time banner plus one line
(the child warms up inside the first execution):

```bash
AFL_PERSISTENT=1 afl-fuzz -i examples/seeds/cnc -o afl-cnc -t 10000 -- \
  jig-emu fuzz -c examples/cnc-p2im.yaml -f CNC --out ./cnc-campaign
```

Do not commit `CNC` or `cnc-campaign/`. A fault is triaged with the usual
path: `crashes/`, `buckets/`, `reports/`. Replay is the `jig-emu run
--input` line in the report. That queues the bytes before boot, which is
not the banner snapshot. To replay against the snapshot, drive
`PersistentHarness.exec_one` with the same machine file.

On this machine a banner checkpoint was 79423 instructions and about 1.9
seconds, and the TX ended in `Grbl 0.8c ['$' for help]`. A `$$` from that
snapshot finished in about 49000 instructions; `?` and `$X` finished in
about 10000 to 13000. The recorded campaign is below.

### Recorded run

15 Nov 2026, in-process campaign, `--max-execs 3000 --rng-seed 1`,
against the published CNC ELF (not stored in this tree):

```text
execs: 3000
corpus: 20
crashes: 0
buckets: 0
hangs: 0
edges: 1550
execs/sec: 5.0
seconds: 594.5
rng-seed: 1
```

The banner checkpoint before that timer was 79423 instructions, 1.93
seconds, PC `0x08004006`, 891 bytes of TX ending in the Grbl 0.8c banner.
No fault and no hang in these 3000 executions. The budget was spent in
the deterministic byte walk of the seeds and the new edges that walk
opened; this is not an AFL havoc marathon and not a claim that Grbl has
no bugs. The corpus past the six seeds is the realtime characters and
short variants the walk found: `!` (feed hold), `~` (cycle start),
`\x18` (ctrl-x, the soft reset named in the help text), CR, NUL, DEL,
`(`, `/`, and a couple of two-byte combinations of those. ctrl-x from
the snapshot did not fault. It printed a fresh `Grbl 0.8c` banner and
stayed in the poll. On this model that hook does not write
`AIRCR.SYSRESETREQ`.

`?`, `$$`, and `$X` from the same snapshot still produce the alarm
status, the settings list ending in `ok`, and `[Caution: Unlocked]`.

`$H` produced no TX in a spot check and the case ended on the idle gap:
homing does not answer inside 8000 instructions of the line being taken.
A longer idle would be needed to follow that motion. The step timer is
still an instruction count, so a move that does get planned does not take
the microseconds in `$3`.
