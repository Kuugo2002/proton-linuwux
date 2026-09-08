#!/usr/bin/env python3

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Result:
    level: str
    name: str
    detail: str = ""
    path: Path | None = None
    hints: tuple[str, ...] = ()


class Diagnostics:
    def __init__(self, source_tree: Path, stage: str):
        self.source_tree = source_tree
        self.stage = stage
        self.results: list[Result] = []

        self.wine = source_tree / "wine"
        self.signal = self.wine / "dlls/ntdll/unix/signal_x86_64.c"
        self.virtual = self.wine / "dlls/ntdll/unix/virtual.c"
        self.unix_private = self.wine / "dlls/ntdll/unix/unix_private.h"
        self.hooks = self.wine / "dlls/ntdll/unix/linuwux_hooks.h"
        self.protocol = self.wine / "server/protocol.def"
        self.fd = self.wine / "server/fd.c"
        self.wine_inf = self.wine / "loader/wine.inf.in"
        self.proton = source_tree / "proton"
        self.make_requests = self.wine / "tools/make_requests"
        self.server_protocol = self.wine / "include/wine/server_protocol.h"
        self.request_handlers = self.wine / "server/request_handlers.h"

    def add(
        self,
        level: str,
        name: str,
        detail: str = "",
        path: Path | None = None,
        *hints: str,
    ):
        self.results.append(
            Result(level, name, detail, path, tuple(hints))
        )

    def pass_(self, name: str, detail: str = ""):
        self.add("PASS", name, detail)

    def warn(
        self,
        name: str,
        detail: str = "",
        path: Path | None = None,
        *hints: str,
    ):
        self.add("WARN", name, detail, path, *hints)

    def fail(
        self,
        name: str,
        detail: str = "",
        path: Path | None = None,
        *hints: str,
    ):
        self.add("FAIL", name, detail, path, *hints)

    @staticmethod
    def read(path: Path) -> str | None:
        try:
            return path.read_text(errors="replace")
        except OSError:
            return None

    @staticmethod
    def last_nonempty(text: str) -> str:
        for line in reversed(text.splitlines()):
            if line.strip():
                return line
        return ""

    @staticmethod
    def exact_line_count(text: str, line: str) -> int:
        return sum(1 for candidate in text.splitlines() if candidate == line)

    @staticmethod
    def substring_count(text: str, needle: str) -> int:
        return text.count(needle)

    def require_file(self, path: Path, description: str) -> bool:
        if path.is_file():
            self.pass_(description, str(path))
            return True

        self.fail(description, f"missing: {path}", path)
        return False

    def expect_count(
        self,
        path: Path,
        text: str,
        needle: str,
        expected: int,
        description: str,
        *,
        exact_line: bool = False,
        hints: tuple[str, ...] = (),
    ):
        if exact_line:
            count = self.exact_line_count(text, needle)
        else:
            count = self.substring_count(text, needle)

        if count == expected:
            self.pass_(description, f"count={count}")
        else:
            self.fail(
                description,
                f"expected count={expected}, observed count={count}",
                path,
                *(hints or (needle,)),
            )

    def expect_absent(
        self,
        path: Path,
        text: str,
        needle: str,
        description: str,
        *hints: str,
    ):
        count = text.count(needle)

        if count == 0:
            self.pass_(description)
        else:
            self.fail(
                description,
                f"expected absent, observed count={count}",
                path,
                *(hints or (needle,)),
            )

    def expect_present(
        self,
        path: Path,
        text: str,
        needle: str,
        description: str,
        *hints: str,
    ):
        count = text.count(needle)

        if count >= 1:
            self.pass_(description, f"count={count}")
        else:
            self.fail(
                description,
                "expected value not found",
                path,
                *(hints or (needle,)),
            )

    @staticmethod
    def sigsys_anchor_count(text: str) -> int:
        in_legacy = False
        in_modern = False
        count = 0

        for line in text.splitlines():
            if line == "#ifdef HAVE_SECCOMP":
                in_legacy = True
                continue

            if in_legacy and line == "#endif":
                in_legacy = False

            if line == "#if defined(__APPLE__) || defined(__linux__)":
                in_modern = True
                continue

            if in_modern and line == "#endif":
                in_modern = False

            if (
                (in_legacy or in_modern)
                and 'TRACE_(seh)("SIGSYS, rax' in line
            ):
                count += 1

        return count

    @staticmethod
    def cpuid_segv_anchor_count(text: str) -> int:
        in_segv = False
        count = 0

        for line in text.splitlines():
            if (
                line
                == "static void segv_handler( int signal, "
                "siginfo_t *siginfo, void *sigcontext )"
            ):
                in_segv = True
                continue

            if in_segv and line == "}":
                in_segv = False

            if (
                in_segv
                and "rec.ExceptionAddress = (void *)RIP_sig(ucontext);"
                in line
            ):
                count += 1

        return count

    def common_files(self) -> dict[Path, str] | None:
        required = [
            (self.signal, "Wine signal_x86_64.c"),
            (self.virtual, "Wine virtual.c"),
            (self.unix_private, "Wine unix_private.h"),
            (self.protocol, "Wine server protocol.def"),
            (self.fd, "Wine server fd.c"),
            (self.wine_inf, "Wine loader wine.inf.in"),
            (self.proton, "Proton launcher"),
            (self.make_requests, "Wine server request generator"),
        ]

        ok = True

        for path, description in required:
            if not self.require_file(path, description):
                ok = False

        if not ok:
            return None

        contents: dict[Path, str] = {}

        for path, _ in required:
            text = self.read(path)

            if text is None:
                self.fail(
                    "Readable source file",
                    f"unable to read: {path}",
                    path,
                )
                ok = False
            else:
                contents[path] = text

        return contents if ok else None

    def detect_backend_source(self, signal_text: str):
        sud = self.exact_line_count(
            signal_text,
            "static LONG syscall_dispatch_enabled = TRUE;",
        )
        legacy = self.exact_line_count(
            signal_text,
            "static void install_bpf(struct sigaction *sig_act)",
        )

        if sud == 1 and legacy == 0:
            self.pass_("Wine syscall backend", "sud")
        elif sud == 0 and legacy == 1:
            self.pass_("Wine syscall backend", "legacy-bpf")
        else:
            self.fail(
                "Wine syscall backend",
                f"unsupported or ambiguous: sud={sud}, legacy-bpf={legacy}",
                self.signal,
                "syscall_dispatch_enabled",
                "install_bpf",
            )

    def diagnose_source(self):
        contents = self.common_files()

        if contents is None:
            return

        signal = contents[self.signal]
        virtual = contents[self.virtual]
        unix_private = contents[self.unix_private]
        protocol = contents[self.protocol]
        fd = contents[self.fd]
        wine_inf = contents[self.wine_inf]
        proton = contents[self.proton]

        if self.hooks.exists():
            self.fail(
                "LinUwUx hooks destination",
                "already exists in an unpatched source tree",
                self.hooks,
            )
        else:
            self.pass_("LinUwUx hooks destination is absent")

        self.expect_absent(
            self.wine_inf,
            wine_inf,
            'HKLM,System\\CurrentControlSet\\Control\\IDConfigDB\\'
            'Hardware Profiles\\0001,"HwProfileGuid",,"'
            '{12345678-1234-1234-1234-123456789012}"',
            "HwProfileGuid not already injected",
            "HwProfileGuid",
        )

        proton_markers = (
            '"winmm": "n,b",',
            '"version.dll": "n,b",',
            '"reflex.dll": "n,b",',
            '"d3d9": "n,b",',
            '"d3d10": "n,b",',
            '"d3d11": "n,b",',
            '"d3d12": "n,b",',
            '"dinput8": "n,b",',
            '"dsound": "n,b",',
            '"dxgi": "n,b",',
            '"hid": "n,b",',
            '"wininet": "n,b",',
            '"winhttp": "n,b",',
            'if "PROTON_DISABLE_LSTEAMCLIENT" not in os.environ:',
        )

        present_markers = [
            marker for marker in proton_markers if marker in proton
        ]

        if present_markers:
            self.fail(
                "LinUwUx Proton overrides not already present",
                f"found {len(present_markers)} integration marker(s)",
                self.proton,
                "PROTON_DISABLE_LSTEAMCLIENT",
                '"winmm": "n,b",',
                '"d3d11": "n,b",',
            )
        else:
            self.pass_("LinUwUx Proton overrides not already present")

        self.expect_count(
            self.proton,
            proton,
            '                "winebth.sys": "d", '
            "#disable winebth.sys as it crashes winedevice.exe",
            1,
            "Proton dlloverrides anchor",
            exact_line=True,
            hints=("winebth.sys",),
        )

        self.expect_count(
            self.proton,
            proton,
            "        # CW Bug 21737. Locoland executable "
            "happens to be steam.exe.",
            1,
            "Proton Locoland anchor",
            exact_line=True,
            hints=("Locoland", "CW Bug 21737"),
        )

        self.expect_count(
            self.wine_inf,
            wine_inf,
            ";;Other app-specific overrides",
            1,
            "wine.inf app-specific overrides anchor",
            exact_line=True,
            hints=("app-specific overrides",),
        )

        self.expect_count(
            self.fd,
            fd,
            "timeout_t monotonic_time;",
            1,
            "fd.c faketime state anchor",
            exact_line=True,
            hints=("monotonic_time",),
        )

        self.expect_count(
            self.fd,
            fd,
            "current_time = (timeout_t)now.tv_sec * TICKS_PER_SEC "
            "+ now.tv_usec * 10 + ticks_1601_to_1970;",
            1,
            "fd.c current_time anchor",
            hints=("current_time =", "ticks_1601_to_1970"),
        )

        fd_last = self.last_nonempty(fd)

        if fd_last == "}":
            self.pass_("fd.c terminal structure", "last non-empty line is '}'")
        else:
            self.fail(
                "fd.c terminal structure",
                f"last non-empty line: {fd_last!r}",
                self.fd,
            )

        self.expect_absent(
            self.protocol,
            protocol,
            "@REQ(set_faketime)",
            "set_faketime not already present in protocol.def",
            "set_faketime",
        )

        protocol_last = self.last_nonempty(protocol)

        if protocol_last == "@END":
            self.pass_(
                "protocol.def terminal structure",
                "last non-empty line is '@END'",
            )
        else:
            self.fail(
                "protocol.def terminal structure",
                f"last non-empty line: {protocol_last!r}",
                self.protocol,
                "@END",
            )

        self.expect_absent(
            self.signal,
            signal,
            '#include "linuwux_hooks.h"',
            "LinUwUx hooks not already included",
            "linuwux_hooks.h",
        )

        self.expect_count(
            self.signal,
            signal,
            '#include "wine/debug.h"',
            1,
            "signal_x86_64.c wine/debug.h anchor",
            exact_line=True,
            hints=("wine/debug.h",),
        )

        sigsys = self.sigsys_anchor_count(signal)

        if sigsys == 1:
            self.pass_("SIGSYS injection anchor", "count=1")
        else:
            self.fail(
                "SIGSYS injection anchor",
                f"expected count=1, observed count={sigsys}",
                self.signal,
                'TRACE_(seh)("SIGSYS, rax',
                "HAVE_SECCOMP",
                "defined(__APPLE__)",
            )

        cpuid = self.cpuid_segv_anchor_count(signal)

        if cpuid == 1:
            self.pass_("CPUID/segv injection anchor", "count=1")
        else:
            self.fail(
                "CPUID/segv injection anchor",
                f"expected count=1, observed count={cpuid}",
                self.signal,
                "segv_handler",
                "ExceptionAddress",
                "RIP_sig",
            )

        self.expect_count(
            self.signal,
            signal,
            "if (sigaction( SIGSEGV, &sig_act, NULL ) == -1) goto error;",
            1,
            "CPUID initialization anchor",
            hints=("sigaction( SIGSEGV",),
        )

        self.expect_absent(
            self.virtual,
            virtual,
            "virtual_map_user_shared_data_write_alias",
            "Writable KUSER alias API not already present",
            "virtual_map_user_shared_data",
        )

        self.expect_count(
            self.virtual,
            virtual,
            "/***********************************************************************\n"
            " *           virtual_map_user_shared_data\n"
            " */\n",
            1,
            "virtual.c writable-alias insertion anchor",
            hints=("virtual_map_user_shared_data",),
        )

        self.expect_absent(
            self.unix_private,
            unix_private,
            "virtual_map_user_shared_data_write_alias",
            "Writable KUSER alias declaration not already present",
            "virtual_map_user_shared_data",
        )

        self.expect_count(
            self.unix_private,
            unix_private,
            "extern void virtual_map_user_shared_data(void);\n",
            1,
            "unix_private.h writable-alias declaration anchor",
            hints=("virtual_map_user_shared_data",),
        )

        self.detect_backend_source(signal)

    def diagnose_post_apply(self):
        contents = self.common_files()

        if contents is None:
            return

        signal = contents[self.signal]
        virtual = contents[self.virtual]
        unix_private = contents[self.unix_private]
        protocol = contents[self.protocol]
        fd = contents[self.fd]
        wine_inf = contents[self.wine_inf]
        proton = contents[self.proton]

        if self.hooks.is_file():
            self.pass_("LinUwUx hooks installed", str(self.hooks))
        else:
            self.fail(
                "LinUwUx hooks installed",
                f"missing: {self.hooks}",
                self.hooks,
            )

        self.expect_present(
            self.signal,
            signal,
            '#include "linuwux_hooks.h"',
            "LinUwUx hooks included in signal_x86_64.c",
            "wine/debug.h",
        )

        for needle, description in (
            (
                "detect_cpu_vendor();",
                "CPU vendor initialization",
            ),
            (
                "linuwux_prepare_kuser_write_alias();",
                "Writable KUSER alias initialization",
            ),
            (
                "linuwux_debug_init();",
                "LinUwUx diagnostics initialization",
            ),
            (
                "syscall(SYS_arch_prctl, ARCH_SET_CPUID, 0);",
                "CPUID faulting initialization",
            ),
            (
                "linuwux_handle_sigsys(sigcontext)",
                "LinUwUx SIGSYS hook",
            ),
            (
                "linuwux_handle_cpuid(siginfo, ucontext)",
                "LinUwUx CPUID hook",
            ),
        ):
            self.expect_present(
                self.signal,
                signal,
                needle,
                description,
                needle.split("(")[0],
            )

        self.expect_present(
            self.virtual,
            virtual,
            "KUSER_SHARED_DATA *virtual_map_user_shared_data_write_alias(void)",
            "Writable KUSER alias implementation",
            "virtual_map_user_shared_data_write_alias",
        )

        self.expect_present(
            self.unix_private,
            unix_private,
            "virtual_map_user_shared_data_write_alias(void);",
            "Writable KUSER alias declaration",
            "virtual_map_user_shared_data_write_alias",
        )

        self.expect_present(
            self.protocol,
            protocol,
            "@REQ(set_faketime)",
            "set_faketime protocol request",
            "set_faketime",
        )

        self.expect_present(
            self.fd,
            fd,
            "static timeout_t faketime = 0;",
            "faketime state",
            "faketime",
        )

        self.expect_present(
            self.fd,
            fd,
            "current_time = (timeout_t)now.tv_sec * TICKS_PER_SEC "
            "+ now.tv_usec * 10 + ticks_1601_to_1970 - faketime;",
            "faketime-adjusted current_time",
            "current_time =",
            "faketime",
        )

        self.expect_present(
            self.fd,
            fd,
            "DECL_HANDLER(set_faketime)",
            "set_faketime handler",
            "set_faketime",
        )

        self.expect_present(
            self.fd,
            fd,
            "faketime = ((current_time >> 32) - req->faketime) << 32;",
            "set_faketime calculation",
            "req->faketime",
        )

        self.expect_present(
            self.wine_inf,
            wine_inf,
            'HKLM,System\\CurrentControlSet\\Control\\IDConfigDB\\'
            'Hardware Profiles\\0001,"HwProfileGuid",,"'
            '{12345678-1234-1234-1234-123456789012}"',
            "LinUwUx HwProfileGuid",
            "HwProfileGuid",
        )

        overrides = (
            "winmm",
            "version.dll",
            "reflex.dll",
            "d3d9",
            "d3d10",
            "d3d11",
            "d3d12",
            "dinput8",
            "dsound",
            "dxgi",
            "hid",
            "wininet",
            "winhttp",
        )

        for override in overrides:
            self.expect_present(
                self.proton,
                proton,
                f'"{override}": "n,b",',
                f"Proton override: {override}",
                override,
            )

        for needle, description in (
            (
                'if "PROTON_DISABLE_LSTEAMCLIENT" not in os.environ:',
                "PROTON_DISABLE_LSTEAMCLIENT guard",
            ),
            (
                'os.environ["PROTON_DISABLE_LSTEAMCLIENT"] = "1"',
                "PROTON_DISABLE_LSTEAMCLIENT os.environ value",
            ),
            (
                'self.env["PROTON_DISABLE_LSTEAMCLIENT"] = "1"',
                "PROTON_DISABLE_LSTEAMCLIENT self.env value",
            ),
        ):
            self.expect_present(
                self.proton,
                proton,
                needle,
                description,
                "PROTON_DISABLE_LSTEAMCLIENT",
            )

        if self.server_protocol.is_file():
            server_protocol = self.read(self.server_protocol) or ""

            self.expect_present(
                self.server_protocol,
                server_protocol,
                "struct set_faketime_request",
                "Generated set_faketime request structure",
                "set_faketime",
            )

            self.expect_present(
                self.server_protocol,
                server_protocol,
                "REQ_set_faketime",
                "Generated set_faketime request table entry",
                "set_faketime",
            )
        else:
            self.fail(
                "Generated server_protocol.h",
                f"missing: {self.server_protocol}",
                self.server_protocol,
            )

        if self.request_handlers.is_file():
            handlers = self.read(self.request_handlers) or ""

            self.expect_present(
                self.request_handlers,
                handlers,
                "DECL_HANDLER(set_faketime);",
                "Generated set_faketime request handler declaration",
                "set_faketime",
            )
        else:
            self.fail(
                "Generated request_handlers.h",
                f"missing: {self.request_handlers}",
                self.request_handlers,
            )

        sud_true = self.exact_line_count(
            signal,
            "static LONG syscall_dispatch_enabled = TRUE;",
        )
        sud_false = self.substring_count(
            signal,
            "static LONG syscall_dispatch_enabled = FALSE;",
        )
        install_bpf = self.exact_line_count(
            signal,
            "static void install_bpf(struct sigaction *sig_act)",
        )

        if sud_true == 0 and install_bpf == 1:
            self.pass_(
                "Post-apply syscall backend",
                f"legacy-bpf (SUD-disabled markers={sud_false})",
            )
        else:
            self.fail(
                "Post-apply syscall backend",
                f"unexpected topology: sud-true={sud_true}, "
                f"sud-false={sud_false}, install_bpf={install_bpf}",
                self.signal,
                "syscall_dispatch_enabled",
                "install_bpf",
            )

        self.expect_absent(
            self.signal,
            signal,
            "if (!syscall_dispatch_enabled)",
            "Stale SUD retry fallback absent",
            "syscall_dispatch_enabled",
            "retry the syscall",
        )

        self.expect_count(
            self.signal,
            signal,
            "RAX_sig(ucontext) == 0xffff",
            1,
            "Legacy BPF probe",
            hints=("0xffff", "STATUS_INVALID_PARAMETER"),
        )

        self.expect_count(
            self.signal,
            signal,
            "RAX_sig(ucontext) = STATUS_INVALID_PARAMETER;",
            1,
            "Legacy BPF probe result",
            hints=("STATUS_INVALID_PARAMETER",),
        )

        self.expect_present(
            self.signal,
            signal,
            "__wine_syscall_dispatcher_prolog_end_ptr",
            "Normal Wine syscall dispatcher redirect",
            "__wine_syscall_dispatcher_prolog_end_ptr",
        )

    def auto_stage(self) -> str:
        signal = self.read(self.signal) or ""

        post_markers = 0

        if self.hooks.is_file():
            post_markers += 1
        if '#include "linuwux_hooks.h"' in signal:
            post_markers += 1
        if "linuwux_handle_cpuid" in signal:
            post_markers += 1

        if post_markers == 0:
            return "source"

        return "post-apply"

    def nearby_context(self, result: Result):
        if not result.path or not result.path.is_file():
            return

        text = self.read(result.path)

        if text is None:
            return

        lines = text.splitlines()
        matches: list[int] = []

        for hint in result.hints:
            if not hint:
                continue

            for index, line in enumerate(lines):
                if hint in line:
                    if index not in matches:
                        matches.append(index)
                    if len(matches) >= 3:
                        break

            if len(matches) >= 3:
                break

        if not matches:
            print("       nearby context: no related text found")
            return

        print("       nearby context:")

        shown: set[int] = set()

        for match in matches:
            start = max(0, match - 2)
            end = min(len(lines), match + 3)

            for index in range(start, end):
                if index in shown:
                    continue

                marker = ">" if index == match else " "
                print(
                    f"       {marker} {index + 1:6d}: "
                    f"{lines[index]}"
                )
                shown.add(index)

            print("       ---")

    def print_report(self) -> int:
        failures = 0
        warnings = 0
        passes = 0

        print("LinUwUx Rework diagnostics")
        print(f"Source tree: {self.source_tree}")
        print(f"Stage: {self.stage}")
        print()

        for result in self.results:
            print(f"[{result.level}] {result.name}")

            if result.detail:
                print(f"       {result.detail}")

            if result.level == "FAIL":
                failures += 1
                self.nearby_context(result)
            elif result.level == "WARN":
                warnings += 1
                self.nearby_context(result)
            else:
                passes += 1

        print()
        print(
            "Summary: "
            f"PASS={passes} WARN={warnings} FAIL={failures}"
        )

        if failures:
            print("Result: FAIL")
            return 1

        if warnings:
            print("Result: PASS with observations")
            return 0

        print("Result: PASS")
        return 0


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Read-only diagnostics for LinUwUx Rework "
            "Proton/Wine source trees."
        )
    )

    parser.add_argument(
        "--source-tree",
        required=True,
        type=Path,
        help="Proton source tree containing wine/ and proton",
    )

    parser.add_argument(
        "--stage",
        choices=("source", "post-apply", "auto"),
        default="auto",
        help="diagnostic stage (default: auto)",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        source_tree = args.source_tree.expanduser().resolve()
    except OSError as exc:
        print(
            f"diagnose.py: unable to resolve source tree: {exc}",
            file=sys.stderr,
        )
        return 2

    if not source_tree.is_dir():
        print(
            f"diagnose.py: source tree not found: {source_tree}",
            file=sys.stderr,
        )
        return 2

    diagnostics = Diagnostics(source_tree, args.stage)

    stage = args.stage

    if stage == "auto":
        stage = diagnostics.auto_stage()
        diagnostics.stage = f"auto -> {stage}"

    if stage == "source":
        diagnostics.diagnose_source()
    elif stage == "post-apply":
        diagnostics.diagnose_post_apply()
    else:
        print(
            f"diagnose.py: unsupported stage: {stage}",
            file=sys.stderr,
        )
        return 2

    return diagnostics.print_report()


if __name__ == "__main__":
    raise SystemExit(main())
