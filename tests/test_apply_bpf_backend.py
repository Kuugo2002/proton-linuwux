"""Regression coverage for GE/CachyOS SIGSYS layouts (no network needed)."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


HELPER = Path(__file__).resolve().parents[1] / "scripts/linuwux/apply_bpf_backend.py"

FALLBACK = """    if (!syscall_dispatch_enabled)
    {
        prctl( PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_OFF, 0, 0, 0 );
        RIP_sig(ucontext) -= 2;  /* retry the syscall */
        return;
    }
"""

NATIVE = """    if (hack_native_syscalls && (RIP_sig(ucontext) >> 32) > 0x7000)
    {
        struct amd64_thread_data *thread_data = (struct amd64_thread_data *)&get_current_teb()->GdiTebBatch;

        TRACE_(seh)( "handling native syscall.\\n" );
        prctl( PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON, 0x700100000000, 0x7fffffff0000 - 0x700100000000,
               &thread_data->syscall_dispatch );
        RIP_sig(ucontext) -= 2;
        return;
    }
"""

EOS = """    /* HACK: The EOS version of easy anti cheat executes linux syscalls in a high address
     * to evade the older seccomp based syscall emulation. */
    if ((long)RIP_sig(ucontext) >= 0x700100000000 && use_eos_syscall_hack)
    {
        RAX_sig(ucontext) = syscall(RAX_sig(ucontext), RDI_sig(ucontext), RSI_sig(ucontext),
                                    RDX_sig(ucontext), R10_sig(ucontext), R8_sig(ucontext),
                                    R9_sig(ucontext));
        return;
    }
"""


def source(body):
    return """static LONG syscall_dispatch_enabled = TRUE;
#if defined(__APPLE__) || defined(__linux__)
static void sigsys_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    extern const void *__wine_syscall_dispatcher_prolog_end_ptr;
    ucontext_t *ucontext = init_handler( sigcontext );
    struct syscall_frame *frame = get_syscall_frame();

    if (linuwux_handle_sigsys(sigcontext))
    {
        leave_handler(ucontext);
        return;
    }
    TRACE_(seh)("SIGSYS, rax %#llx, rip %#llx.\\n", RAX_sig(ucontext), RIP_sig(ucontext));

""" + body + """
    frame->rip = RIP_sig(ucontext) + 0xb;
    frame->rcx = RIP_sig(ucontext);
    RIP_sig(ucontext) = (ULONG64)__wine_syscall_dispatcher_prolog_end_ptr;
}
#endif

void signal_init_process(void)
{
    struct sigaction sig_act;

    return;

 error:
    exit(1);
}
"""


class BpfBackendTests(unittest.TestCase):
    def transform(self, original, error=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "signal_x86_64.c"
            path.write_text(original)
            before = path.read_bytes()
            result = subprocess.run(
                [sys.executable, str(HELPER), str(path)],
                capture_output=True, text=True,
            )
            if error:
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(error, result.stderr)
                self.assertEqual(path.read_bytes(), before)
            else:
                self.assertEqual(result.returncode, 0, result.stderr)
            return path.read_text()

    def test_supported_layouts(self):
        # The GE preparation patch adds EOS after the native workaround.
        # CachyOS has only the native workaround. Older stacks have EOS only.
        for name, workaround in (
            ("ge", NATIVE + "\n" + EOS),
            ("cachyos", NATIVE),
            ("older-eos", EOS),
            ("no-workaround", ""),
        ):
            for fallback in ("", FALLBACK, FALLBACK + "\n"):
                with self.subTest(layout=name, fallback=repr(fallback)):
                    original = source("#ifdef __linux__\n" + fallback + workaround + "#endif\n")
                    transformed = self.transform(original)
                    handler = transformed.split("static void sigsys_handler", 1)[1].split("\n}\n", 1)[0]
                    self.assertNotIn("if (!syscall_dispatch_enabled)", handler)
                    self.assertEqual(handler.count("RAX_sig(ucontext) == 0xffff"), 1)
                    self.assertEqual(handler.count("RAX_sig(ucontext) = STATUS_INVALID_PARAMETER;"), 1)
                    self.assertIn("#ifdef __linux__\n    if (RAX_sig(ucontext) == 0xffff)", handler)
                    self.assertIn(workaround + "#endif", handler)
                    self.assertIn("leave_handler(ucontext);", handler)
                    self.assertIn("RIP_sig(ucontext) = (ULONG64)__wine_syscall_dispatcher_prolog_end_ptr;", handler)
                    self.assertIn("static LONG syscall_dispatch_enabled = FALSE;", transformed)
                    self.assertEqual(transformed.count("install_bpf(&sig_act);"), 1)

    def test_nested_guard_is_preserved(self):
        body = "#ifdef __linux__\n#ifdef SOME_OPTION\n" + NATIVE + "#endif\n" + EOS + "#endif\n"
        self.transform(source(body))

    def test_missing_linux_guard_fails_without_writing(self):
        self.transform(source(EOS), "expected exactly one Linux block")

    def test_duplicate_linux_guard_fails_without_writing(self):
        self.transform(source("#ifdef __linux__\n#endif\n" * 2), "expected exactly one Linux block")

    def test_unclosed_linux_guard_fails_without_writing(self):
        self.transform(source("#ifdef __linux__\n" + EOS), "Linux guard is incomplete")

    def test_eos_outside_linux_guard_fails_without_writing(self):
        self.transform(source("#ifdef __linux__\n#endif\n" + EOS), "not in the same Linux block")

    def test_changed_fallback_fails_without_writing(self):
        fallback = FALLBACK.replace("/* retry the syscall */", "/* changed upstream */")
        self.transform(source("#ifdef __linux__\n" + fallback + NATIVE + "#endif\n"), "stale SUD retry fallback remained")

    def test_alternative_linux_branch_fails_without_writing(self):
        self.transform(source("#ifdef __linux__\n#else\n#endif\n"), "unexpected alternative branch")


if __name__ == "__main__":
    unittest.main()
