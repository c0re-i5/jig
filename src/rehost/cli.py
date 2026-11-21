# SPDX-License-Identifier: MIT
"""Command line: load a machine file and an image the caller already has."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from rehost import __version__
from rehost.backends import available_backends
from rehost.errors import RehostError
from rehost.fixtures import fixture_summary, list_fixtures
from rehost.fuzz import FuzzHarness, is_fuzz_crash, read_input
from rehost.machine import Machine
from rehost.peripherals import available_plugins
from rehost.result import EXIT_USAGE, format_report
from rehost.triage import ReplayTarget, TriageStore, note_crash


def cli() -> None:
    sys.exit(main())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="jig-emu",
        description=(
            "Jig: a machine shop for plant-controller firmware "
            "(emulate, instrument, fuzz, triage). "
            "jig-emu does not download or bundle firmware. "
            "The Python import package is rehost."
        ),
    )
    parser.add_argument("--version", action="version", version=f"jig-emu {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="Execute an image until halt, fault, or timeout")
    _add_machine_source(run)
    run.add_argument(
        "--backend",
        choices=("unicorn", "qemu", "renode", "riscv"),
        help=(
            "CPU engine. unicorn (default) is in-process Cortex-M. "
            "qemu drives qemu-system-arm on the mps2-an385 board and "
            "dispatches decoded MMIO to the same plugins. "
            "renode drives the renode monitor on the nrf52840 Cortex-M "
            "platform and dispatches decoded MMIO to the same plugins. "
            "riscv is in-process RV32 (Unicorn). The machine file's arch "
            "selects it too: arch: riscv or arch: riscv32. "
            "qemu-system-arm or renode must be on PATH for those engines."
        ),
    )
    run.add_argument(
        "--input",
        help="Fuzz input file applied before execution. Use - to read stdin.",
    )
    run.add_argument("--snapshot-out", help="Write a JSON snapshot after the run")
    run.add_argument(
        "--dump",
        action="append",
        default=[],
        metavar="ADDR:SIZE",
        help="Hex-dump guest memory after the run. Repeatable.",
    )
    run.add_argument("-v", "--verbose", action="store_true", help="Print registers and the MMIO trace")
    modbus = run.add_mutually_exclusive_group()
    modbus.add_argument(
        "--modbus-read",
        metavar="SLAVE:ADDRESS:COUNT",
        help="Queue a Modbus RTU Read Holding Registers (0x03) request on the UART before running",
    )
    modbus.add_argument(
        "--modbus-write",
        metavar="SLAVE:ADDRESS:VALUE",
        help="Queue a Modbus RTU Write Single Register (0x06) request on the UART before running",
    )
    run.add_argument(
        "--modbus-uart",
        help="UART peripheral for --modbus-read / --modbus-write (default: the only UART)",
    )
    run.add_argument(
        "--serial-in",
        action="append",
        default=[],
        metavar="TEXT",
        help="ASCII chunk for UART RX. Repeatable. Escapes: \\n \\r \\t \\\\ \\xHH. "
        "With --serial-idle each chunk is its own line; otherwise the chunks are concatenated.",
    )
    run.add_argument(
        "--serial-file",
        help="Raw bytes queued on UART RX as one chunk. Combined with --serial-in.",
    )
    run.add_argument(
        "--serial-uart",
        help="UART for --serial-in / --serial-file (default: the only UART)",
    )
    run.add_argument(
        "--serial-after",
        type=int,
        metavar="N",
        help="Queue serial RX once N instructions have retired (0 queues before the first)",
    )
    run.add_argument(
        "--serial-idle",
        type=int,
        metavar="N",
        help="Queue the next serial chunk after TX has been quiet for N instructions. "
        "The first chunk waits until TX has grown, so a banner can finish first.",
    )
    run.add_argument(
        "--serial-settle",
        type=int,
        metavar="N",
        help="Before the last --serial-in / --serial-file chunk, wait N extra instructions. "
        "Requires --serial-idle. Use it when the guest keeps working after it has stopped transmitting.",
    )

    fuzz = sub.add_parser(
        "fuzz",
        help="Coverage-guided fuzzing, in-process or under an AFL++ forkserver",
    )
    _add_machine_source(fuzz)
    fuzz.add_argument(
        "--out",
        help="Directory for the corpus, crashes, and hangs. Required unless afl-fuzz is attached.",
    )
    fuzz.add_argument(
        "--input",
        help="One seed file, or - for stdin. Under afl-fuzz without shared-memory "
        "testcases this path is re-read every iteration (pass @@).",
    )
    fuzz.add_argument("--seeds", help="Directory of seed files. Names are tried in sorted order.")
    fuzz.add_argument(
        "--max-execs",
        type=int,
        default=1_000_000,
        help="Stop the in-process campaign after this many executions (default: 1000000).",
    )
    fuzz.add_argument(
        "--rng-seed",
        type=int,
        help="Seed the havoc RNG. Printed in the summary when omitted.",
    )
    fuzz.add_argument(
        "--stop-on-crash",
        action="store_true",
        help="Return after the first crash. The crashing input is still written to --out.",
    )
    fuzz.add_argument(
        "--persistent-iters",
        type=int,
        default=10_000,
        help="Under afl-fuzz, restart the persistent child after this many cases (default: 10000).",
    )
    fuzz.add_argument(
        "--cmplog",
        action="store_true",
        help="In-process CmpLog stage: on each new corpus input, log compare "
        "operands during a shadow run and replace matching input bytes "
        "(endian swap, plus or minus one). Off by default. Ignored when an "
        "AFL++ forkserver is attached.",
    )
    fuzz.add_argument("-v", "--verbose", action="store_true")

    triage = sub.add_parser(
        "triage",
        help="Classify crash inputs under --out and rewrite bucket reports",
    )
    _add_machine_source(triage)
    triage.add_argument(
        "--out",
        required=True,
        help="Campaign directory that contains crashes/.",
    )
    triage.add_argument("-v", "--verbose", action="store_true")

    plugins = sub.add_parser("plugins", help="List MMIO plugins and CPU backends")
    plugins.add_argument("-v", "--verbose", action="store_true")

    fixtures = sub.add_parser("fixtures", help="List built-in synthetic fixtures")
    fixtures.add_argument("-v", "--verbose", action="store_true")

    inspect = sub.add_parser(
        "inspect",
        help="Read an ELF or Intel HEX image and print a suggested memory map",
    )
    inspect.add_argument(
        "firmware",
        help="ELF32 or Intel HEX you already have. Not executed, and not fetched.",
    )
    inspect.add_argument(
        "--aggressive",
        action="store_true",
        help=(
            "Include guessed RCC/MCG register blocks and UART stubs in the report. "
            "The default report leaves those constants unimplemented."
        ),
    )

    map_parser = sub.add_parser(
        "map",
        help="Write a starter machine file from an ELF or Intel HEX image",
    )
    map_sub = map_parser.add_subparsers(dest="map_cmd", required=True)
    init = map_sub.add_parser(
        "init",
        help="Write starter YAML. Does not emulate the image.",
    )
    init.add_argument(
        "firmware",
        help="ELF32 or Intel HEX you already have. Not executed, and not fetched.",
    )
    init.add_argument(
        "-o",
        "--output",
        help="YAML path to write. Omit to print the YAML on stdout.",
    )
    init.add_argument(
        "--name",
        help="Machine name. Default: the firmware file's stem.",
    )
    init.add_argument(
        "--force",
        action="store_true",
        help="Overwrite --output if it already exists.",
    )
    init.add_argument(
        "--aggressive",
        action="store_true",
        help=(
            "Promote a recognized RCC/MCG constant to a register_block and a "
            "UART-like constant to a uart stub. Those rules are guesses. "
            "The default scaffold leaves the windows unimplemented."
        ),
    )

    args = parser.parse_args(argv)
    configure_logging(getattr(args, "verbose", False))
    try:
        if args.cmd == "plugins":
            return _plugins()
        if args.cmd == "fixtures":
            return _fixtures()
        if args.cmd == "inspect":
            return _inspect(args)
        if args.cmd == "map":
            return _map_init(args)
        if args.cmd == "fuzz":
            return _fuzz(args)
        if args.cmd == "triage":
            return _triage(args)
        return _run(args)
    except RehostError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")
    else:
        root.setLevel(level)
    logging.getLogger("rehost").setLevel(level)


def _plugins() -> int:
    print("peripherals:")
    described = {
        "uart": "TX byte log, RX queue, status flags, optional RX IRQ",
        "gpio": "output latch, sampled input, optional BSRR set/reset",
        "systick": "per-instruction CTRL/LOAD/VAL/CALIB",
        "timer": "instruction-paced counter that can pend an IRQ",
        "register_block": "config-defined 32-bit registers, with optional follow bits",
        "bitband": "Cortex-M bit-band alias onto a target address",
        "unimplemented": "log the access and return read_default",
    }
    for name in available_plugins():
        print(f"  {name:<16} {described.get(name, '')}")
    print("backends:")
    for name in available_backends():
        print(f"  {name}")
    return 0


def _read_user_image(path: str) -> bytes:
    """Bytes of an image the caller already has. Nothing is downloaded."""
    file = Path(path)
    if not file.is_file():
        raise RehostError(f"firmware image not found: {file}")
    data = file.read_bytes()
    if not data:
        raise RehostError(f"firmware image is empty: {file}")
    return data


def _inspect(args: argparse.Namespace) -> int:
    from rehost.mapinit import format_inspection, inspect_image

    info = inspect_image(_read_user_image(args.firmware), aggressive=args.aggressive)
    print(format_inspection(info))
    return 0


def _map_init(args: argparse.Namespace) -> int:
    from rehost.mapinit import inspect_image, machine_name_from_stem, render_machine_yaml

    blob = _read_user_image(args.firmware)
    info = inspect_image(blob, aggressive=args.aggressive)
    name = args.name or machine_name_from_stem(Path(args.firmware).stem)
    text = render_machine_yaml(info, name=name)
    if args.output:
        dest = Path(args.output)
        if dest.exists() and not args.force:
            raise RehostError(f"{dest} already exists; pass --force to overwrite")
        dest.write_text(text, encoding="utf-8")
        print(f"wrote {dest}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


def _fixtures() -> int:
    for name in list_fixtures():
        print(f"{name:<12} {fixture_summary(name)}")
    return 0


def _add_machine_source(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-c",
        "--config",
        help="Machine YAML or TOML. Required with --firmware. Defaults to the fixture's machine file.",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "-f",
        "--firmware",
        help=(
            "Firmware image you are authorized to analyze. "
            "A raw bin is copied to load.base. "
            "ELF32 (little-endian ARM) and Intel HEX (.hex, .ihex) are "
            "written at the addresses in the file. Detection uses the bytes, "
            "not the file name."
        ),
    )
    source.add_argument(
        "--fixture",
        choices=list_fixtures(),
        help="Built-in synthetic program (Thumb or RV32I; no external firmware)",
    )
    parser.add_argument("--timeout-ms", type=int, help="Override run.timeout_ms")
    parser.add_argument("--max-instructions", type=int, help="Override run.max_instructions")


def _select_backend(args: argparse.Namespace):
    """The engine for this command. None keeps the machine file's ``arch``."""
    choice = getattr(args, "backend", None)
    if choice is None:
        return None
    if choice == "unicorn":
        from rehost.backends.unicorn_cortexm import UnicornCortexM

        return UnicornCortexM()
    if choice == "qemu":
        from rehost.backends.qemu_cortexm import QemuCortexM

        return QemuCortexM()
    if choice == "renode":
        from rehost.backends.renode_cortexm import RenodeCortexM

        return RenodeCortexM()
    if choice == "riscv":
        from rehost.backends.unicorn_riscv import UnicornRiscv

        return UnicornRiscv()
    raise RehostError(f"unknown backend {choice!r}. Available: unicorn, qemu, renode, riscv.")


def _machine_from_args(args: argparse.Namespace) -> Machine:
    if args.firmware and not args.config:
        raise RehostError("--firmware requires --config (the tool does not guess a memory map)")
    backend = _select_backend(args)
    if args.fixture and not args.config:
        machine = Machine.from_fixture(args.fixture, backend=backend)
    else:
        machine = Machine.from_path(args.config, backend=backend)
        if args.fixture:
            from rehost.fixtures import build_fixture

            machine.load_image(build_fixture(args.fixture))
        else:
            path = Path(args.firmware)
            if not path.exists() or path.is_dir():
                raise RehostError(f"firmware image not found: {path}")
            machine.load_image(path.read_bytes())
    if args.timeout_ms is not None:
        if args.timeout_ms < 0:
            raise RehostError("--timeout-ms must be >= 0")
        machine.config.run.timeout_ms = args.timeout_ms
    if args.max_instructions is not None:
        if args.max_instructions < 0:
            raise RehostError("--max-instructions must be >= 0")
        machine.config.run.max_instructions = args.max_instructions
    if machine.config.run.timeout_ms == 0 and machine.config.run.max_instructions == 0:
        raise RehostError("set a timeout or an instruction limit so the run cannot hang")
    return machine


def _fuzz(args: argparse.Namespace) -> int:
    from rehost.campaign import Campaign
    from rehost.forkserver import forkserver_fd, serve

    if args.max_execs < 1:
        raise RehostError("--max-execs must be >= 1")
    if args.persistent_iters < 1:
        raise RehostError("--persistent-iters must be >= 1")
    if args.rng_seed is not None and args.rng_seed < 0:
        raise RehostError("--rng-seed must be >= 0")
    replay = _replay_target(args)
    ctl = forkserver_fd()
    if ctl is not None:
        if args.cmplog:
            print(
                "cmplog: ignored under the AFL++ forkserver; afl-fuzz keeps mutating",
                file=sys.stderr,
            )
        out = Path(args.out) if args.out else None
        return serve(
            lambda: _machine_from_args(args),
            ctl_fd=ctl,
            out=out,
            persistent_iters=args.persistent_iters,
            input_path=None if args.input in (None, "-") else args.input,
            replay=replay,
        )
    if not args.out:
        raise RehostError("jig-emu fuzz requires --out (or an AFL++ forkserver on fd 198)")
    machine = _machine_from_args(args)
    seed_files: list[Path] = []
    if args.seeds:
        directory = Path(args.seeds)
        if not directory.is_dir():
            raise RehostError(f"seed directory not found: {directory}")
        seed_files = [path for path in sorted(directory.iterdir()) if path.is_file()]
    extra: list[bytes] = []
    if args.input == "-":
        extra.append(sys.stdin.buffer.read())
    elif args.input:
        path = Path(args.input)
        if not path.is_file():
            raise RehostError(f"fuzz input not found: {path}")
        extra.append(path.read_bytes())
    campaign = Campaign(
        machine,
        out=Path(args.out),
        seed_files=seed_files,
        extra_inputs=extra,
        max_execs=args.max_execs,
        rng_seed=args.rng_seed,
        stop_on_crash=args.stop_on_crash,
        replay=replay,
        cmplog=args.cmplog,
    )
    print(campaign.run().format())
    return 0


def _triage(args: argparse.Namespace) -> int:
    from rehost.coverage import MAP_SIZE, CoverageMap
    from rehost.fuzz import PersistentHarness, ensure_fuzz_backend

    out = Path(args.out)
    crashes = out / "crashes"
    if not crashes.is_dir():
        raise RehostError(f"no crashes directory at {crashes}")
    machine = _machine_from_args(args)
    ensure_fuzz_backend(machine)
    machine.attach_coverage(CoverageMap(size=MAP_SIZE))
    harness = PersistentHarness(machine)
    store = TriageStore(out, replay=_replay_target(args))
    store.reset()
    files = sorted(path for path in crashes.iterdir() if path.is_file())
    for path in files:
        data = path.read_bytes()
        try:
            result = harness.exec_one(data)
        except RehostError as exc:
            print(f"skip {path.name}: {exc}", file=sys.stderr)
            continue
        if not is_fuzz_crash(result, machine.config.fuzz):
            print(f"skip {path.name}: {result.status} {result.detail}", file=sys.stderr)
            continue
        note_crash(store, machine, data, result, crash_path=path)
    print(store.summary())
    return 0


def _replay_target(args: argparse.Namespace) -> ReplayTarget:
    """Flags that replay one input against the machine this command loaded."""
    parts: list[str] = []
    if args.config:
        parts.extend(["--config", str(Path(args.config).resolve())])
    if args.fixture:
        parts.extend(["--fixture", args.fixture])
    elif args.firmware:
        parts.extend(["--firmware", str(Path(args.firmware).resolve())])
    if getattr(args, "timeout_ms", None) is not None:
        parts.extend(["--timeout-ms", str(args.timeout_ms)])
    if getattr(args, "max_instructions", None) is not None:
        parts.extend(["--max-instructions", str(args.max_instructions)])
    return ReplayTarget(tuple(parts))


def _run(args: argparse.Namespace) -> int:
    machine = _machine_from_args(args)
    try:
        data = _read_run_input(args, machine)
        if data is not None:
            FuzzHarness(machine).apply(data)
        _queue_modbus(args, machine)
        _queue_serial(args, machine)
        result = machine.run()
        dumps = [_dump_line(machine, spec) for spec in args.dump]
        print(
            format_report(
                result,
                name=machine.config.name,
                peripheral_lines=_peripheral_lines(machine),
                verbose=args.verbose,
                dumps=dumps,
            )
        )
        if args.snapshot_out:
            machine.snapshot().write_json(args.snapshot_out)
        return result.exit_code()
    finally:
        close = getattr(machine.backend, "close", None)
        if close is not None:
            close()


def _queue_modbus(args: argparse.Namespace, machine: Machine) -> None:
    """Queue one RTU request when the run command asked for one."""
    if not args.modbus_read and not args.modbus_write:
        return
    from rehost.modbus import deliver, read_holding_registers, write_single_register

    if args.modbus_read:
        slave, address, count = _modbus_triple(args.modbus_read, "SLAVE:ADDRESS:COUNT")
        frame = read_holding_registers(slave, address, count)
    else:
        slave, address, value = _modbus_triple(args.modbus_write, "SLAVE:ADDRESS:VALUE")
        frame = write_single_register(slave, address, value)
    deliver(machine, frame, uart=args.modbus_uart)


def _queue_serial(args: argparse.Namespace, machine: Machine) -> None:
    """Queue UART RX from ``--serial-in`` / ``--serial-file``, now or mid-run."""
    chunks = _serial_chunks(args)
    if (
        not chunks
        and args.serial_after is None
        and args.serial_idle is None
        and args.serial_settle is None
        and not args.serial_uart
    ):
        return
    if not chunks:
        raise RehostError(
            "--serial-after, --serial-idle, --serial-settle, and --serial-uart "
            "need --serial-in or --serial-file"
        )
    if args.serial_after is not None and args.serial_after < 0:
        raise RehostError("--serial-after must be >= 0")
    if args.serial_idle is not None and args.serial_idle < 1:
        raise RehostError("--serial-idle must be >= 1")
    if args.serial_settle is not None and args.serial_settle < 0:
        raise RehostError("--serial-settle must be >= 0")
    if args.serial_settle and args.serial_idle is None:
        raise RehostError("--serial-settle requires --serial-idle")
    from rehost.serial import attach_feed, deliver

    settles = None
    if args.serial_settle:
        settles = [0] * len(chunks)
        settles[-1] = args.serial_settle

    if args.serial_idle is None and (args.serial_after is None or args.serial_after == 0):
        deliver(machine, b"".join(chunks), uart=args.serial_uart)
        return
    if args.serial_idle is None:
        # One shot after N instructions. Chunks share that moment.
        attach_feed(
            machine,
            [b"".join(chunks)],
            uart=args.serial_uart,
            after_instructions=args.serial_after,
        )
        return
    attach_feed(
        machine,
        chunks,
        uart=args.serial_uart,
        after_instructions=args.serial_after,
        idle_instructions=args.serial_idle,
        settle_before=settles,
    )


def _serial_chunks(args: argparse.Namespace) -> list[bytes]:
    from rehost.serial import decode_escapes

    chunks: list[bytes] = []
    for text in args.serial_in:
        chunks.append(decode_escapes(text))
    if args.serial_file:
        path = Path(args.serial_file)
        if not path.is_file():
            raise RehostError(f"serial file not found: {path}")
        chunks.append(path.read_bytes())
    return chunks


def _modbus_triple(text: str, shape: str) -> tuple[int, int, int]:
    parts = text.split(":")
    if len(parts) != 3 or not all(parts):
        raise RehostError(f"Modbus request must be {shape}")
    try:
        return tuple(int(part, 0) for part in parts)  # type: ignore[return-value]
    except ValueError as exc:
        raise RehostError(f"Modbus request must be {shape}") from exc


def _read_run_input(args: argparse.Namespace, machine: Machine) -> bytes | None:
    """Pick a testcase. Stdin is read only for ``--input -`` or a fuzz-configured machine."""
    import os

    if args.input == "-":
        return read_input(stdin=sys.stdin.buffer)
    if args.input:
        return read_input(path=args.input)
    if (
        os.environ.get("__AFL_SHM_FUZZ_ID")
        or os.environ.get("__AFL_SHM_FUZZ_FD")
        or os.environ.get("REHOST_INPUT_FILE")
    ):
        return read_input()
    if (
        machine.config.fuzz is not None
        and sys.stdin is not None
        and not sys.stdin.isatty()
    ):
        return read_input(stdin=sys.stdin.buffer)
    return None


def _peripheral_lines(machine: Machine) -> list[str]:
    lines: list[str] = []
    for plugin in machine.peripherals:
        lines.extend(plugin.debug_lines())
    return lines


def _dump_line(machine: Machine, spec: str) -> str:
    if ":" not in spec:
        raise RehostError(f"--dump {spec!r} must be address:size")
    addr_text, size_text = spec.split(":", 1)
    try:
        address = int(addr_text, 0)
        size = int(size_text, 0)
    except ValueError as exc:
        raise RehostError(f"--dump {spec!r} must be address:size") from exc
    if size < 0 or size > 4096:
        raise RehostError("--dump size must be between 0 and 4096")
    data = machine.read_memory(address, size)
    parts = [f"dump {address:#010x}:"]
    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]
        hexpart = " ".join(f"{byte:02x}" for byte in chunk)
        parts.append(f"  {address + offset:08x}  {hexpart}")
    return "\n".join(parts)
