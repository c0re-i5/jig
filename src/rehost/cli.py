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
from rehost.fuzz import FuzzHarness, read_input
from rehost.machine import Machine
from rehost.peripherals import available_plugins
from rehost.result import EXIT_USAGE, format_report


def cli() -> None:
    sys.exit(main())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="jig-emu",
        description=(
            "Rehost a firmware image you are authorized to analyze. "
            "jig-emu does not download or bundle firmware."
        ),
    )
    parser.add_argument("--version", action="version", version=f"jig-emu {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="Execute an image until halt, fault, or timeout")
    _add_machine_source(run)
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
    fuzz.add_argument("-v", "--verbose", action="store_true")

    plugins = sub.add_parser("plugins", help="List MMIO plugins and CPU backends")
    plugins.add_argument("-v", "--verbose", action="store_true")

    fixtures = sub.add_parser("fixtures", help="List built-in synthetic fixtures")
    fixtures.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args(argv)
    configure_logging(getattr(args, "verbose", False))
    try:
        if args.cmd == "plugins":
            return _plugins()
        if args.cmd == "fixtures":
            return _fixtures()
        if args.cmd == "fuzz":
            return _fuzz(args)
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
        "uart": "TX byte log, RX queue, status flags",
        "gpio": "output latch and sampled input",
        "systick": "polling model of CTRL/LOAD/VAL/CALIB",
        "register_block": "config-defined 32-bit registers",
        "unimplemented": "log the access and return read_default",
    }
    for name in available_plugins():
        print(f"  {name:<16} {described.get(name, '')}")
    print("backends:")
    for name in available_backends():
        print(f"  {name}")
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
        help="Path to a firmware image you are authorized to analyze",
    )
    source.add_argument(
        "--fixture",
        choices=list_fixtures(),
        help="Built-in synthetic Cortex-M program (no external firmware)",
    )
    parser.add_argument("--timeout-ms", type=int, help="Override run.timeout_ms")
    parser.add_argument("--max-instructions", type=int, help="Override run.max_instructions")


def _machine_from_args(args: argparse.Namespace) -> Machine:
    if args.firmware and not args.config:
        raise RehostError("--firmware requires --config (the tool does not guess a memory map)")
    if args.fixture and not args.config:
        machine = Machine.from_fixture(args.fixture)
    else:
        machine = Machine.from_path(args.config)
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
    ctl = forkserver_fd()
    if ctl is not None:
        out = Path(args.out) if args.out else None
        return serve(
            lambda: _machine_from_args(args),
            ctl_fd=ctl,
            out=out,
            persistent_iters=args.persistent_iters,
            input_path=None if args.input in (None, "-") else args.input,
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
    )
    print(campaign.run().format())
    return 0


def _run(args: argparse.Namespace) -> int:
    machine = _machine_from_args(args)
    data = _read_run_input(args, machine)
    if data is not None:
        FuzzHarness(machine).apply(data)
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
