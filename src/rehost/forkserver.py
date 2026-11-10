# SPDX-License-Identifier: MIT
"""AFL++ persistent-mode forkserver.

This is the target side of the v1 handshake in AFL++ ``afl-compiler-rt.o.c``
(``__afl_start_forkserver`` / ``__afl_persistent_loop``) and the constants in
``include/config.h`` and ``include/types.h`` on the stable branch:

* control pipe ``FORKSRV_FD`` (198), status pipe ``FORKSRV_FD + 1``
* hello word ``0x41464c00 + FS_NEW_VERSION_MAX`` (version 1), parent replies
  with that word XOR ``0xffffffff``
* option word ``FS_NEW_OPT_MAPSIZE`` plus ``FS_NEW_OPT_SHDMEM_FUZZ`` when the
  fuzz region is present, then the 32-bit map size, then the version word again
* each iteration: read a 32-bit ``was_killed``, fork or ``SIGCONT``, write the
  child pid, ``waitpid(WUNTRACED)``, write the raw wait status

Persistent iterations stop with ``SIGSTOP``. afl-fuzz treats ``WIFSTOPPED`` as
a finished execution and keeps the child. A guest fault, or a PC listed in
``fuzz.crash_addresses``, raises ``SIGSEGV`` so the status is ``WIFSIGNALED``.
The testcase is left in the fuzz shared memory for afl-fuzz to copy, and is
also written under ``--out/crashes`` when that directory was requested.
The same crash is classified and merged into ``--out/buckets`` and
``--out/reports`` before the process is killed.

``FS_NEW_OPT_FUTEX`` is not advertised. Current AFL++ falls back to this
SIGSTOP path when the target does not offer the child-sync word. CmpLog,
IJON, and the bug-pass map are not part of the handshake.

The forkserver process does not construct a Unicorn engine. The child does,
after ``fork``, and then loops on ``PersistentHarness.exec_one``. Forking the
engine itself is avoided on purpose.
"""

from __future__ import annotations

import ctypes
import mmap
import os
import signal
import stat
import sys
import traceback
from collections.abc import Callable
from pathlib import Path

from rehost.coverage import MAP_SIZE, CoverageMap
from rehost.errors import FuzzInputError, RehostError
from rehost.fuzz import PersistentHarness, is_fuzz_crash, read_afl_shmem
from rehost.triage import ReplayTarget, TriageStore, note_crash

# include/config.h
FORKSRV_FD = 198
SHM_ENV_VAR = "__AFL_SHM_ID"
SHM_FD_ENV_VAR = "__AFL_SHM_FD"

# include/types.h — new forkserver, version 1.
FS_NEW_VERSION_MAX = 1
FS_VERSION = 0x41464C00 + FS_NEW_VERSION_MAX
FS_NEW_OPT_MAPSIZE = 0x00000001
FS_NEW_OPT_SHDMEM_FUZZ = 0x00000002

# afl-fuzz scans a *compiled* target for this. jig-emu is a Python entry
# point, so the scan does not see it. Set AFL_PERSISTENT=1 in the afl-fuzz
# environment when a build uses that flag to label the campaign. The status
# word still carries WIFSTOPPED either way.
PERSISTENT_SIGNATURE = b"##SIG_AFL_PERSISTENT##"


def forkserver_fd() -> int | None:
    """Return the control fd if this process was spawned as an AFL++ forkserver.

    Stock afl-fuzz dups the pipes onto 198 and 199 and does not set
    ``AFL_FORKSRV_FD``. That variable is honored so a test (or a wrapper) can
    point at another consecutive pair. A fd that is not a pipe is ignored, so
    an unrelated open descriptor cannot divert ``jig-emu fuzz`` into this loop.
    """
    raw = os.environ.get("AFL_FORKSRV_FD")
    if raw is None:
        fd = FORKSRV_FD
    else:
        try:
            fd = int(raw)
        except ValueError:
            return None
    if fd < 0:
        return None
    try:
        control = os.fstat(fd)
        status = os.fstat(fd + 1)
    except OSError:
        return None
    if not stat.S_ISFIFO(control.st_mode) or not stat.S_ISFIFO(status.st_mode):
        return None
    return fd


def serve(
    load_machine: Callable[[], object],
    *,
    ctl_fd: int,
    out: Path | None,
    persistent_iters: int,
    input_path: str | None,
    replay: ReplayTarget | None = None,
) -> int:
    """Speak the forkserver protocol. ``load_machine`` runs in the child only."""
    if persistent_iters < 1:
        print("error: --persistent-iters must be >= 1", file=sys.stderr)
        return 2
    status_fd = ctl_fd + 1
    if not _handshake(ctl_fd, status_fd):
        return 1
    child_pid = 0
    child_stopped = False
    try:
        while True:
            try:
                was_killed = _read_u32(ctl_fd)
            except EOFError:
                return 0
            except OSError:
                return 0
            if child_stopped and was_killed:
                _kill_child(child_pid)
                child_stopped = False
            resumed = False
            if child_stopped:
                try:
                    os.kill(child_pid, signal.SIGCONT)
                except OSError:
                    child_stopped = False
                else:
                    child_stopped = False
                    resumed = True
            if not resumed:
                try:
                    child_pid = os.fork()
                except OSError as exc:
                    print(f"error: fork failed: {exc}", file=sys.stderr)
                    return 1
                if child_pid == 0:
                    _close_quiet(ctl_fd)
                    _close_quiet(status_fd)
                    _child_main(
                        load_machine,
                        out=out,
                        persistent_iters=persistent_iters,
                        input_path=input_path,
                        replay=replay,
                    )
                    os._exit(0)
            if not _write_u32(status_fd, child_pid & 0xFFFFFFFF):
                return 0
            status = _wait_untraced(child_pid)
            if os.WIFSTOPPED(status):
                child_stopped = True
            else:
                # Reaped. Drop the pid so process-exit cleanup cannot signal a
                # recycled pid after the child has already been waited on.
                child_stopped = False
                child_pid = 0
            if not _write_u32(status_fd, status & 0xFFFFFFFF):
                return 0
    finally:
        # A stopped child, or one still running because the status pipe closed
        # before waitpid, must not be left behind. A reaped child has pid 0.
        if child_pid > 0:
            _kill_child(child_pid)


def _handshake(ctl_fd: int, status_fd: int) -> bool:
    """Version-1 hello. False means the parent is not an AFL++ forkserver."""
    if not _write_u32(status_fd, FS_VERSION):
        return False
    try:
        reply = _read_u32(ctl_fd)
    except (EOFError, OSError):
        return False
    if reply != (FS_VERSION ^ 0xFFFFFFFF):
        print("error: AFL++ forkserver replied with an unexpected version word", file=sys.stderr)
        return False
    options = FS_NEW_OPT_MAPSIZE
    if os.environ.get("__AFL_SHM_FUZZ_ID") or os.environ.get("__AFL_SHM_FUZZ_FD"):
        options |= FS_NEW_OPT_SHDMEM_FUZZ
    if not _write_u32(status_fd, options):
        return False
    if not _write_u32(status_fd, MAP_SIZE):
        return False
    return _write_u32(status_fd, FS_VERSION)


def _child_main(
    load_machine: Callable[[], object],
    *,
    out: Path | None,
    persistent_iters: int,
    input_path: str | None,
    replay: ReplayTarget | None,
) -> None:
    try:
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        _disable_cores()
        _persistent_loop(
            load_machine,
            out=out,
            persistent_iters=persistent_iters,
            input_path=input_path,
            replay=replay,
        )
    except RehostError as exc:
        print(f"error: {exc}", file=sys.stderr)
        os._exit(1)
    except SystemExit:
        raise
    except BaseException:
        traceback.print_exc()
        _disable_cores()
        signal.signal(signal.SIGABRT, signal.SIG_DFL)
        os.kill(os.getpid(), signal.SIGABRT)
        os._exit(128 + signal.SIGABRT)


def _persistent_loop(
    load_machine: Callable[[], object],
    *,
    out: Path | None,
    persistent_iters: int,
    input_path: str | None,
    replay: ReplayTarget | None,
) -> None:
    machine = load_machine()
    coverage = _map_afl_coverage()
    machine.attach_coverage(coverage)
    harness = PersistentHarness(machine)
    # Checkpoint at boot, before any fuzzer bytes, including NVIC state.
    harness.checkpoint()
    triage = TriageStore(out, replay=replay) if out is not None else None
    remaining = persistent_iters
    first = True
    while remaining > 0:
        if not first:
            os.kill(os.getpid(), signal.SIGSTOP)
        first = False
        remaining -= 1
        data = _read_iteration(input_path)
        result = harness.exec_one(data)
        if is_fuzz_crash(result, machine.config.fuzz):
            path = _preserve_crash(out, data, result)
            if triage is not None:
                try:
                    note_crash(triage, machine, data, result, crash_path=path)
                except Exception:
                    traceback.print_exc()
            _die_as_crash()
    os._exit(0)


def _read_iteration(input_path: str | None) -> bytes:
    """Prefer the AFL++ fuzz region. Otherwise re-read ``--input`` (the ``@@`` path)."""
    if os.environ.get("__AFL_SHM_FUZZ_ID") or os.environ.get("__AFL_SHM_FUZZ_FD"):
        shared = read_afl_shmem()
        if shared is None:
            raise FuzzInputError("AFL++ fuzz region disappeared during a persistent iteration")
        return shared
    if input_path:
        return Path(input_path).read_bytes()
    return b""


def _map_afl_coverage() -> CoverageMap:
    """Attach the coverage bitmap afl-fuzz created.

    ``__AFL_SHM_FD`` is preferred when both are set, matching current AFL++.
    Only ``MAP_SIZE`` bytes are mapped: the fuzzer may place a child-sync word
    past the bitmap, and this target does not use it.
    """
    fd_env = os.environ.get(SHM_FD_ENV_VAR)
    if fd_env is not None:
        try:
            fd = int(fd_env)
        except ValueError as exc:
            raise FuzzInputError("__AFL_SHM_FD is not an integer") from exc
        try:
            mapped = mmap.mmap(fd, MAP_SIZE, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
        except (OSError, ValueError) as exc:
            raise FuzzInputError(f"cannot map __AFL_SHM_FD {fd}: {exc}") from exc
        return CoverageMap(mapped)
    id_env = os.environ.get(SHM_ENV_VAR)
    if id_env is None:
        raise FuzzInputError(
            "AFL++ did not pass a coverage map (__AFL_SHM_ID or __AFL_SHM_FD)"
        )
    try:
        shm_id = int(id_env)
    except ValueError as exc:
        raise FuzzInputError("__AFL_SHM_ID is not an integer") from exc
    libc = ctypes.CDLL(None, use_errno=True)
    shmat = libc.shmat
    shmat.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
    shmat.restype = ctypes.c_void_p
    addr = shmat(shm_id, None, 0)
    failed = addr is None or addr == ctypes.c_void_p(-1).value
    if failed:
        err = ctypes.get_errno()
        detail = os.strerror(err) if err else "unknown error"
        raise FuzzInputError(f"shmat({shm_id}) for the coverage map failed: {detail}")
    # Kept alive by the CoverageMap. The segment stays attached for the child.
    buf = (ctypes.c_ubyte * MAP_SIZE).from_address(addr)
    return CoverageMap(buf)


def _preserve_crash(out: Path | None, data: bytes, result) -> Path | None:
    """Write the crashing bytes before the process is killed.

    afl-fuzz copies the fuzz shared memory when it sees the signal. This file
    is a second copy for ``--out``, so a crash is still on disk if that
    directory was requested.
    """
    if out is None:
        return None
    directory = out / "crashes"
    directory.mkdir(parents=True, exist_ok=True)
    name = f"id:000000,pid:{os.getpid()},sig:11,pc:{result.pc & ~1:08x}"
    path = directory / name
    with path.open("wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    return path


def _die_as_crash() -> None:
    """Terminate with SIGSEGV so waitpid reports WIFSIGNALED."""
    _disable_cores()
    signal.signal(signal.SIGSEGV, signal.SIG_DFL)
    os.kill(os.getpid(), signal.SIGSEGV)
    os._exit(128 + signal.SIGSEGV)


def _disable_cores() -> None:
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, OSError, ValueError):
        return


def _kill_child(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        return
    _wait_untraced(pid)


def _wait_untraced(pid: int) -> int:
    while True:
        try:
            _pid, status = os.waitpid(pid, os.WUNTRACED)
        except InterruptedError:
            continue
        return status


def _read_u32(fd: int) -> int:
    return int.from_bytes(_read_exact(fd, 4), "little")


def _read_exact(fd: int, size: int) -> bytes:
    chunks: list[bytes] = []
    got = 0
    while got < size:
        try:
            part = os.read(fd, size - got)
        except InterruptedError:
            continue
        if not part:
            raise EOFError
        chunks.append(part)
        got += len(part)
    return b"".join(chunks)


def _write_u32(fd: int, value: int) -> bool:
    return _write_all(fd, (value & 0xFFFFFFFF).to_bytes(4, "little"))


def _write_all(fd: int, data: bytes) -> bool:
    view = memoryview(data)
    while view:
        try:
            written = os.write(fd, view)
        except InterruptedError:
            continue
        except OSError:
            return False
        if written <= 0:
            return False
        view = view[written:]
    return True


def _close_quiet(fd: int) -> None:
    try:
        os.close(fd)
    except OSError:
        return
