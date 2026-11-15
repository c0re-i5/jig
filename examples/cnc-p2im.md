# P2IM CNC (grbl 0.8c) on stock jig-emu

Stock `jig-emu run` on main has booted a published Cortex-M image to its
application banner. The sample is P2IM CNC: grbl 0.8c on an STM32F407VG.
The precompiled ELF is
[`binary/CNC`](https://github.com/RiS3-Lab/p2im-real_firmware/blob/master/binary/CNC)
in [RiS3-Lab/p2im-real_firmware](https://github.com/RiS3-Lab/p2im-real_firmware).
The same target is written up with a map in the
[Fuzzware P2IM CNC experiment](https://github.com/fuzzware-fuzzer/fuzzware-experiments/tree/main/02-comparison-with-state-of-the-art/P2IM/CNC).

This repository does not contain the ELF or the raw bin. CI executes the
synthetic `plant-floor` fixture. The run below is one local smoke on commit
`06230276f7344c89e8259751e4c98b19200e936e` (14 Nov 2026). The numbers are
that observation. No test in this tree checks them.

The collection's
[LICENSE.md](https://github.com/RiS3-Lab/p2im-real_firmware/blob/master/LICENSE.md)
does not relicense the binaries. It points at each firmware's upstream
project. Grbl is GPLv3. Keep your copy on your machine. Read
[RESPONSIBLE_USE.md](../RESPONSIBLE_USE.md). Other images in that collection
are outside this note.

## Map

[`cnc-p2im.yaml`](cnc-p2im.yaml) is
[`stm32f4_clock.yaml`](stm32f4_clock.yaml) with a name, a description, and
three run limits: `timeout_ms: 15000`, `max_instructions: 2000000`,
`trace_limit: 128`. RCC `follow` and both bit-band windows are the
template's. The smoke left TIM2, GPIO BSRR, and the EEPROM path unmodeled.

The template's own `timeout_ms` is 2000. The recorded smoke set it to
15000 and hit that timeout with the banner already transmitted. The same
boot with the template file is:

```bash
jig-emu run -c examples/stm32f4_clock.yaml -f CNC.bin -v \
  --timeout-ms 15000 --max-instructions 2000000
```

## Raw image

`--firmware` is raw bytes copied to `load.base` (`0x08000000`). Jig does
not parse ELF program headers. Use the published `binary/CNC` ELF. A rebuild
from the `CNC/` sources in that repository is a different image.

```bash
arm-none-eabi-objcopy -O binary CNC CNC.bin
```

That writes the flash image, including the `.data` load-memory address. A
host `objcopy` built without ARM support rejects this ELF. Extract every
`PT_LOAD` whose `p_paddr` lies in flash, and lay those bytes out by
`p_paddr`. The `p_vaddr` of the second segment is SRAM. Dropping it leaves
`.data` out of the image.

| `p_paddr` | `p_vaddr` | `p_filesz` | Contents |
| --- | --- | --- | --- |
| `0x08000000` | `0x08000000` | `0xc0c0` | vectors, code, rodata |
| `0x0800c0c0` | `0x20000000` | `0x44c` | `.data` image in flash |

The two segments are contiguous. The raw file is 50444 bytes. Reset copies
`.data` and clears BSS. The first word stays `0x2001FFFF` (Atollic
`_estack`, odd). Leave it odd. The CPU model clears SP[1:0].

```python
import struct
from pathlib import Path

blob = Path("CNC").read_bytes()
assert blob[:4] == b"\x7fELF" and blob[4] == 1 and blob[5] == 1
phoff = struct.unpack_from("<I", blob, 28)[0]
phentsize, phnum = struct.unpack_from("<HH", blob, 42)
loads = []
for index in range(phnum):
    off = phoff + index * phentsize
    p_type, p_offset, _vaddr, paddr, filesz = struct.unpack_from("<IIIII", blob, off)
    if p_type == 1 and filesz and 0x08000000 <= paddr and paddr + filesz <= 0x08100000:
        loads.append((paddr, blob[p_offset : p_offset + filesz]))
loads.sort()
start = loads[0][0]
end = max(addr + len(chunk) for addr, chunk in loads)
image = bytearray(end - start)
for addr, chunk in loads:
    image[addr - start : addr - start + len(chunk)] = chunk
Path("CNC.bin").write_bytes(image)
```

Check the file before you boot it. The recorded extract is 50444 bytes and
the first word is `0x2001ffff`:

```bash
python3 -c 'b=open("CNC.bin","rb").read(); print(len(b), hex(int.from_bytes(b[:4],"little")))'
```

## Run

```bash
jig-emu run -c examples/cnc-p2im.yaml -f CNC.bin -v \
  --max-instructions 2000000 \
  --snapshot-out cnc.snapshot.json
```

Exit status 2 is a timeout. Exit status 1 is a fault. The recorded run
exited 2: `status: timeout`, `detail: timeout after 15000 ms`, with the
CPU in the Grbl serial poll and an empty USART2 RX.

With `examples/cnc-p2im.yaml` the name line is `p2im-cnc`. The recorded run's
identifying fields were:

```text
status: timeout
detail: timeout after 15000 ms
pc: 0x08007e6c
sp: 0x2001ffbc
lr: 0x08008291
instructions: 673777
systick ctrl: 0x7 load: 0x2903f
```

`load: 0x2903f` is the SysTick reload after clock setup (168000-1). On that
run `sp` was word-aligned at `0x2001ffbc`. The vector table still held the
odd `_estack`. `lr` was `0x08008291`, in the serial poll. The timeout is
wall-clock time, and after the banner the firmware spins on an empty USART2
RX, so the PC and the instruction count are where that host was when 15
seconds elapsed. A repeat keeps the timeout, `load: 0x2903f`, and the
USART2 text. The PC and the instruction count can differ. The report also
prints one line per unimplemented window. Those windows (PWR, SYSCFG, EXTI,
GPIOB, GPIOD, GPIOE, TIM2, and the rest of the template tail) were touched
during init. The banner did not require promoting them.

USART2 TX in the report is the first 32 bytes, as hex, then `(+859 more)`.
The recorded preview is:

```text
usart2 tx: 6572726f723a20454550524f4d2072656164206661696c2e205573696e672064 (+859 more)
```

Those 32 bytes are `error: EEPROM read fail. Using d`. The banner is later
in the buffer. The snapshot keeps the whole TX (891 bytes on this run):

```bash
python3 -c 'import json; tx=json.load(open("cnc.snapshot.json"))["peripherals"]["usart2"]["tx"]["__bytes__"]; print(bytes.fromhex(tx).decode())'
```

Success is that text containing `Grbl 0.8c`. The recorded capture opens
with the firmware's own EEPROM fallback, prints the compiled `$` settings,
and then:

```text
error: EEPROM read fail. Using defaults
$0=157.480 (x, step/mm)
...
Grbl 0.8c ['$' for help]
['$H'|'$X' to unlock]
```

The map has no EEPROM model. Grbl reports the failed read, uses its
compiled defaults, and reaches the protocol banner. The run then waits for
serial input. `jig-emu fuzz` writes a RAM buffer. This machine file has no
`fuzz:` section. The image's input is USART2.
