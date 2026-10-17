#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [[ $# -ne 1 ]]
then
    echo "Usage: $0 <proton-source-dir>" >&2
    exit 1
fi

SOURCE_DIR="$(realpath "$1")"

if [[ ! -d "$SOURCE_DIR/wine/dlls/ntdll/unix" ]]
then
    echo "Error: Wine ntdll Unix source directory not found:" >&2
    echo "$SOURCE_DIR/wine/dlls/ntdll/unix" >&2
    exit 1
fi

HOOKS_SOURCE="$ROOT_DIR/scripts/linuwux/linuwux_hooks.h"
BPF_HELPER="$ROOT_DIR/scripts/linuwux/apply_bpf_backend.py"
HOOKS_DEST="$SOURCE_DIR/wine/dlls/ntdll/unix/linuwux_hooks.h"
SIGNAL_FILE="$SOURCE_DIR/wine/dlls/ntdll/unix/signal_x86_64.c"
VIRTUAL_FILE="$SOURCE_DIR/wine/dlls/ntdll/unix/virtual.c"
UNIX_PRIVATE_FILE="$SOURCE_DIR/wine/dlls/ntdll/unix/unix_private.h"
NTUSER_FILE="$SOURCE_DIR/wine/include/ntuser.h"
USER32_MAIN_FILE="$SOURCE_DIR/wine/dlls/user32/user_main.c"
PROTOCOL_FILE="$SOURCE_DIR/wine/server/protocol.def"
REQUESTS_TOOL="$SOURCE_DIR/wine/tools/make_requests"
FD_FILE="$SOURCE_DIR/wine/server/fd.c"
WINE_INF_FILE="$SOURCE_DIR/wine/loader/wine.inf.in"
PROTON_FILE="$SOURCE_DIR/proton"

# Reject symbolic links before modifying any Wine/Proton source files.
# Otherwise cp or make_requests could overwrite targets outside the
# transaction, leaving changes that rollback cannot restore.
LINUWUX_PROTECTED_PATHS=(
    "$SIGNAL_FILE"
    "$VIRTUAL_FILE"
    "$UNIX_PRIVATE_FILE"
    "$NTUSER_FILE"
    "$USER32_MAIN_FILE"
    "$PROTOCOL_FILE"
    "$FD_FILE"
    "$WINE_INF_FILE"
    "$PROTON_FILE"
    "$SOURCE_DIR/wine/include/wine/server_protocol.h"
    "$SOURCE_DIR/wine/server/request_trace.h"
    "$SOURCE_DIR/wine/server/request_handlers.h"
    "$SOURCE_DIR/wine/include/wine/server_protocol.h.new"
    "$SOURCE_DIR/wine/server/request_trace.h.new"
    "$SOURCE_DIR/wine/server/request_handlers.h.new"
    "$HOOKS_DEST"
)

for LINUWUX_PROTECTED_PATH in "${LINUWUX_PROTECTED_PATHS[@]}"
do
    if [[ -L "$LINUWUX_PROTECTED_PATH" ]]
    then
        echo "Error: symbolic link not allowed in LinUwUx source transaction:" >&2
        echo "$LINUWUX_PROTECTED_PATH" >&2
        exit 1
    fi
done

if [[ ! -f "$HOOKS_SOURCE" ]]
then
    echo "Error: LinUwUx hooks source not found:" >&2
    echo "$HOOKS_SOURCE" >&2
    exit 1
fi

if [[ ! -f "$BPF_HELPER" ]]
then
    echo "Error: LinUwUx BPF helper not found:" >&2
    echo "$BPF_HELPER" >&2
    exit 1
fi

if [[ ! -f "$REQUESTS_TOOL" ]]
then
    echo "Error: Wine server request generator not found:" >&2
    echo "$REQUESTS_TOOL" >&2
    exit 1
fi

if ! command -v perl >/dev/null 2>&1
then
    echo "Error: perl is required to regenerate Wine server protocol files" >&2
    exit 1
fi

if [[ -e "$HOOKS_DEST" ]]
then
    echo "Error: LinUwUx hooks destination already exists:" >&2
    echo "$HOOKS_DEST" >&2
    exit 1
fi

if [[ ! -f "$SIGNAL_FILE" ]]
then
    echo "Error: signal_x86_64.c not found:" >&2
    echo "$SIGNAL_FILE" >&2
    exit 1
fi

if [[ ! -f "$VIRTUAL_FILE" ]]
then
    echo "Error: Wine virtual.c not found:" >&2
    echo "$VIRTUAL_FILE" >&2
    exit 1
fi

if [[ ! -f "$UNIX_PRIVATE_FILE" ]]
then
    echo "Error: Wine unix_private.h not found:" >&2
    echo "$UNIX_PRIVATE_FILE" >&2
    exit 1
fi

if [[ ! -f "$NTUSER_FILE" ]]
then
    echo "Error: Wine ntuser.h not found:" >&2
    echo "$NTUSER_FILE" >&2
    exit 1
fi

if [[ ! -f "$USER32_MAIN_FILE" ]]
then
    echo "Error: Wine user32 user_main.c not found:" >&2
    echo "$USER32_MAIN_FILE" >&2
    exit 1
fi

if grep -Fq 'thread_detached' "$NTUSER_FILE" ||
   grep -Fq 'thread_detached' "$USER32_MAIN_FILE"
then
    echo "Error: Wine thread detach guard is already present" >&2
    exit 1
fi

if [[ ! -f "$PROTOCOL_FILE" ]]
then
    echo "Error: Wine server protocol definition not found:" >&2
    echo "$PROTOCOL_FILE" >&2
    exit 1
fi

if [[ ! -f "$FD_FILE" ]]
then
    echo "Error: Wine server fd.c not found:" >&2
    echo "$FD_FILE" >&2
    exit 1
fi

if [[ ! -f "$WINE_INF_FILE" ]]
then
    echo "Error: Wine loader wine.inf.in not found:" >&2
    echo "$WINE_INF_FILE" >&2
    exit 1
fi

if grep -Fq 'HKLM,System\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001,"HwProfileGuid",,"{12345678-1234-1234-1234-123456789012}"' "$WINE_INF_FILE"
then
    echo "Error: LinUwUx HwProfileGuid is already defined in wine.inf.in" >&2
    exit 1
fi

if [[ ! -f "$PROTON_FILE" ]]
then
    echo "Error: Proton launcher script not found:" >&2
    echo "$PROTON_FILE" >&2
    exit 1
fi

if grep -Fq '"winmm": "n,b",' "$PROTON_FILE" ||
   grep -Fq '"version.dll": "n,b",' "$PROTON_FILE" ||
   grep -Fq '"reflex.dll": "n,b",' "$PROTON_FILE" ||
   grep -Fq '"d3d9": "n,b",' "$PROTON_FILE" ||
   grep -Fq '"d3d10": "n,b",' "$PROTON_FILE" ||
   grep -Fq '"d3d11": "n,b",' "$PROTON_FILE" ||
   grep -Fq '"d3d12": "n,b",' "$PROTON_FILE" ||
   grep -Fq '"dinput8": "n,b",' "$PROTON_FILE" ||
   grep -Fq '"dsound": "n,b",' "$PROTON_FILE" ||
   grep -Fq '"dxgi": "n,b",' "$PROTON_FILE" ||
   grep -Fq '"hid": "n,b",' "$PROTON_FILE" ||
   grep -Fq '"wininet": "n,b",' "$PROTON_FILE" ||
   grep -Fq '"winhttp": "n,b",' "$PROTON_FILE" ||
   grep -Fq 'if "PROTON_DISABLE_LSTEAMCLIENT" not in os.environ:' "$PROTON_FILE"
then
    echo "Error: LinUwUx proton overrides are already present" >&2
    exit 1
fi

PROTON_DLL_OVERRIDE_ANCHOR_COUNT="$(
    grep -c '^                "winebth.sys": "d", #disable winebth.sys as it crashes winedevice.exe$' "$PROTON_FILE" || true
)"

if [[ "$PROTON_DLL_OVERRIDE_ANCHOR_COUNT" -ne 1 ]]
then
    echo "Error: expected exactly one dlloverrides anchor in proton" >&2
    echo "Found: $PROTON_DLL_OVERRIDE_ANCHOR_COUNT" >&2
    exit 1
fi

PROTON_LSTEAMCLIENT_ANCHOR_COUNT="$(
    grep -c '^        # CW Bug 21737. Locoland executable happens to be steam.exe.$' "$PROTON_FILE" || true
)"

if [[ "$PROTON_LSTEAMCLIENT_ANCHOR_COUNT" -ne 1 ]]
then
    echo "Error: expected exactly one Locoland anchor in proton" >&2
    echo "Found: $PROTON_LSTEAMCLIENT_ANCHOR_COUNT" >&2
    exit 1
fi

WINE_INF_OVERRIDES_ANCHOR_COUNT="$(
    grep -c '^;;Other app-specific overrides$' "$WINE_INF_FILE" || true
)"

if [[ "$WINE_INF_OVERRIDES_ANCHOR_COUNT" -ne 1 ]]
then
    echo "Error: expected exactly one app-specific overrides anchor in wine.inf.in" >&2
    echo "Found: $WINE_INF_OVERRIDES_ANCHOR_COUNT" >&2
    exit 1
fi

FD_TIME_ANCHOR_COUNT="$(
    grep -c '^timeout_t monotonic_time;$' "$FD_FILE" || true
)"

if [[ "$FD_TIME_ANCHOR_COUNT" -ne 1 ]]
then
    echo "Error: expected exactly one faketime state anchor in fd.c" >&2
    echo "Found: $FD_TIME_ANCHOR_COUNT" >&2
    exit 1
fi

FD_CURRENT_TIME_ANCHOR_COUNT="$(
    grep -c 'current_time = (timeout_t)now\.tv_sec \* TICKS_PER_SEC + now\.tv_usec \* 10 + ticks_1601_to_1970;' "$FD_FILE" || true
)"

if [[ "$FD_CURRENT_TIME_ANCHOR_COUNT" -ne 1 ]]
then
    echo "Error: expected exactly one current_time anchor in fd.c" >&2
    echo "Found: $FD_CURRENT_TIME_ANCHOR_COUNT" >&2
    exit 1
fi

FD_LAST_LINE="$(
    awk 'NF { line = $0 } END { print line }' "$FD_FILE"
)"

if [[ "$FD_LAST_LINE" != "}" ]]
then
    echo "Error: unexpected end of fd.c" >&2
    echo "Last non-empty line: $FD_LAST_LINE" >&2
    exit 1
fi

if grep -Fq '@REQ(set_faketime)' "$PROTOCOL_FILE"
then
    echo "Error: set_faketime is already defined in protocol.def" >&2
    exit 1
fi

PROTOCOL_LAST_LINE="$(
    awk 'NF { line = $0 } END { print line }' "$PROTOCOL_FILE"
)"

if [[ "$PROTOCOL_LAST_LINE" != "@END" ]]
then
    echo "Error: unexpected end of protocol.def" >&2
    echo "Last non-empty line: $PROTOCOL_LAST_LINE" >&2
    exit 1
fi

if grep -Fq '#include "linuwux_hooks.h"' "$SIGNAL_FILE"
then
    echo "Error: LinUwUx hooks are already included in signal_x86_64.c" >&2
    exit 1
fi

INCLUDE_ANCHOR_COUNT="$(
    grep -c '^#include "wine/debug.h"$' "$SIGNAL_FILE" || true
)"

if [[ "$INCLUDE_ANCHOR_COUNT" -ne 1 ]]
then
    echo "Error: expected exactly one wine/debug.h include anchor in signal_x86_64.c" >&2
    echo "Found: $INCLUDE_ANCHOR_COUNT" >&2
    exit 1
fi

SIGSYS_ANCHOR_COUNT="$(
    awk '
        /^#ifdef HAVE_SECCOMP$/ {
            in_legacy_sigsys = 1
            next
        }

        in_legacy_sigsys && /^#endif$/ {
            in_legacy_sigsys = 0
        }

        /^#if defined\(__APPLE__\) \|\| defined\(__linux__\)$/ {
            in_modern_sigsys = 1
            next
        }

        in_modern_sigsys && /^#endif$/ {
            in_modern_sigsys = 0
        }

        (in_legacy_sigsys || in_modern_sigsys) &&
        /TRACE_\(seh\)\("SIGSYS, rax/ {
            count++
        }

        END { print count + 0 }
    ' "$SIGNAL_FILE"
)"

if [[ "$SIGSYS_ANCHOR_COUNT" -ne 1 ]]
then
    echo "Error: expected exactly one SIGSYS anchor in signal_x86_64.c" >&2
    echo "Found: $SIGSYS_ANCHOR_COUNT" >&2
    exit 1
fi

CPUID_ANCHOR_COUNT="$(
    awk '
        /^static void segv_handler\( int signal, siginfo_t \*siginfo, void \*sigcontext \)$/ {
            in_segv = 1
            next
        }

        in_segv && /^}$/ {
            in_segv = 0
        }

        in_segv && /rec\.ExceptionAddress = \(void \*\)RIP_sig\(ucontext\);/ {
            count++
        }

        END { print count + 0 }
    ' "$SIGNAL_FILE"
)"

if [[ "$CPUID_ANCHOR_COUNT" -ne 1 ]]
then
    echo "Error: expected exactly one CPUID/segv anchor in signal_x86_64.c" >&2
    echo "Found: $CPUID_ANCHOR_COUNT" >&2
    exit 1
fi

CPUID_INIT_ANCHOR_COUNT="$(
    grep -c 'if (sigaction( SIGSEGV, &sig_act, NULL ) == -1) goto error;' "$SIGNAL_FILE" || true
)"

if [[ "$CPUID_INIT_ANCHOR_COUNT" -ne 1 ]]
then
    echo "Error: expected exactly one CPUID init anchor in signal_x86_64.c" >&2
    echo "Found: $CPUID_INIT_ANCHOR_COUNT" >&2
    exit 1
fi

SUD_ENABLE_ANCHOR_COUNT="$(
    grep -c '^static LONG syscall_dispatch_enabled = TRUE;$' "$SIGNAL_FILE" || true
)"

LEGACY_BPF_ANCHOR_COUNT="$(
    grep -c '^static void install_bpf(struct sigaction \*sig_act)$' "$SIGNAL_FILE" || true
)"

if [[ "$SUD_ENABLE_ANCHOR_COUNT" -eq 1 && "$LEGACY_BPF_ANCHOR_COUNT" -eq 0 ]]
then
    LINUWUX_SYSCALL_BACKEND="sud"
elif [[ "$SUD_ENABLE_ANCHOR_COUNT" -eq 0 && "$LEGACY_BPF_ANCHOR_COUNT" -eq 1 ]]
then
    LINUWUX_SYSCALL_BACKEND="legacy-bpf"
else
    echo "Error: unsupported or ambiguous Wine syscall backend" >&2
    echo "SUD enable anchors: $SUD_ENABLE_ANCHOR_COUNT" >&2
    echo "Legacy BPF anchors: $LEGACY_BPF_ANCHOR_COUNT" >&2
    exit 1
fi

TRANSACTION_DIR="$(mktemp -d)"
TRANSACTION_READY=0

SIGNAL_TMP="$TRANSACTION_DIR/signal.tmp"
VIRTUAL_TMP="$TRANSACTION_DIR/virtual.tmp"
UNIX_PRIVATE_TMP="$TRANSACTION_DIR/unix_private.tmp"
NTUSER_TMP="$TRANSACTION_DIR/ntuser.tmp"
USER32_MAIN_TMP="$TRANSACTION_DIR/user32_main.tmp"
PROTOCOL_TMP="$TRANSACTION_DIR/protocol.tmp"
FD_TMP="$TRANSACTION_DIR/fd.tmp"
WINE_INF_TMP="$TRANSACTION_DIR/wine_inf.tmp"
PROTON_TMP="$TRANSACTION_DIR/proton.tmp"

TRANSACTION_FILES=(
    "$SIGNAL_FILE"
    "$VIRTUAL_FILE"
    "$UNIX_PRIVATE_FILE"
    "$NTUSER_FILE"
    "$USER32_MAIN_FILE"
    "$PROTOCOL_FILE"
    "$FD_FILE"
    "$WINE_INF_FILE"
    "$PROTON_FILE"
    "$SOURCE_DIR/wine/include/wine/server_protocol.h"
    "$SOURCE_DIR/wine/server/request_trace.h"
    "$SOURCE_DIR/wine/server/request_handlers.h"
    "$SOURCE_DIR/wine/include/wine/server_protocol.h.new"
    "$SOURCE_DIR/wine/server/request_trace.h.new"
    "$SOURCE_DIR/wine/server/request_handlers.h.new"
    "$HOOKS_DEST"
)

transaction_cleanup()
{
    local status=$?
    local failed=0
    local i file backup_file

    trap - EXIT ERR INT TERM HUP

    if [[ "$status" -ne 0 && "$TRANSACTION_READY" -eq 1 ]]
    then
        echo "LinUwUx: application failed; restoring source files..." >&2

        for i in "${!TRANSACTION_FILES[@]}"
        do
            file="${TRANSACTION_FILES[$i]}"
            backup_file="$TRANSACTION_DIR/original/$i"

            if [[ -f "$TRANSACTION_DIR/existed/$i" ]]
            then
                if ! cp -a --remove-destination "$backup_file" "$file"
                then
                    echo "ERROR: failed to restore $file" >&2
                    failed=1
                fi
            else
                if ! rm -f "$file"
                then
                    echo "ERROR: failed to remove generated file $file" >&2
                    failed=1
                fi
            fi
        done
    fi

    if [[ "$failed" -ne 0 ]]
    then
        echo "ERROR: rollback incomplete; backups retained at $TRANSACTION_DIR" >&2
        exit 1
    fi

    rm -rf -- "$TRANSACTION_DIR" || {
        echo "WARNING: cannot remove transaction directory: $TRANSACTION_DIR" >&2
        exit 1
    }

    exit "$status"
}

trap transaction_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

mkdir -p "$TRANSACTION_DIR/original" "$TRANSACTION_DIR/existed"

for i in "${!TRANSACTION_FILES[@]}"
do
    file="${TRANSACTION_FILES[$i]}"

    if [[ -e "$file" || -L "$file" ]]
    then
        cp -a "$file" "$TRANSACTION_DIR/original/$i"
        touch "$TRANSACTION_DIR/existed/$i"
    fi
done

TRANSACTION_READY=1

python3 - "$VIRTUAL_FILE" "$VIRTUAL_TMP" <<'PYVIRTUAL'
from pathlib import Path
import sys

src = Path(sys.argv[1]).read_text()
dst = Path(sys.argv[2])

if "virtual_map_user_shared_data_write_alias" in src:
    raise SystemExit(
        "Error: writable user-shared-data alias API already present"
    )

anchor = """/***********************************************************************
 *           virtual_map_user_shared_data
 */
"""

if src.count(anchor) != 1:
    raise SystemExit(
        "Error: expected exactly one virtual_map_user_shared_data anchor"
    )

func = """/*
 * Return a writable alias of the process user shared data section.
 *
 * The canonical KUSER_SHARED_DATA mapping remains read-only.
 * This view aliases the same MAP_SHARED backing object.
 */
KUSER_SHARED_DATA *virtual_map_user_shared_data_write_alias(void)
{
    UNICODE_STRING name_str = RTL_CONSTANT_STRING( shared_data_nameW );
    OBJECT_ATTRIBUTES attr = { sizeof(attr), 0, &name_str };
    KUSER_SHARED_DATA *data;
    unsigned int status;
    HANDLE section;
    int res, fd, needs_close;

    if ((status = NtOpenSection( &section, SECTION_ALL_ACCESS, &attr )))
    {
        ERR( "failed to open the USD section for writable alias: %08x\\\\n",
             status );
        return NULL;
    }

    res = server_get_unix_fd(
        section, 0, &fd, &needs_close, NULL, NULL );

    if (res)
    {
        NtClose( section );
        return NULL;
    }

    data = mmap(
        NULL, page_size,
        PROT_READ | PROT_WRITE,
        MAP_SHARED, fd, 0 );

    if (needs_close)
        close( fd );

    NtClose( section );

    if (data == MAP_FAILED)
        return NULL;

    return data;
}


"""

dst.write_text(src.replace(anchor, func + anchor, 1))
PYVIRTUAL


python3 - "$UNIX_PRIVATE_FILE" "$UNIX_PRIVATE_TMP" <<'PYPRIVATE'
from pathlib import Path
import sys

src = Path(sys.argv[1]).read_text()
dst = Path(sys.argv[2])

if "virtual_map_user_shared_data_write_alias" in src:
    raise SystemExit(
        "Error: writable user-shared-data alias declaration already present"
    )

anchor = "extern void virtual_map_user_shared_data(void);\n"

decl = """extern struct _KUSER_SHARED_DATA *
virtual_map_user_shared_data_write_alias(void);
"""

if src.count(anchor) != 1:
    raise SystemExit(
        "Error: expected exactly one virtual_map_user_shared_data declaration"
    )

dst.write_text(src.replace(anchor, anchor + decl, 1))
PYPRIVATE


python3 - "$NTUSER_FILE" "$NTUSER_TMP" <<'PYNTUSER'
from pathlib import Path
import re
import sys

src = Path(sys.argv[1]).read_text()
dst = Path(sys.argv[2])

if "thread_detached" in src:
    raise SystemExit(
        "Error: thread_detached already present in ntuser.h"
    )

pattern = r'^([ \t]*UINT64[ \t]+wmchar_data;[^\n]*\n)'
matches = re.findall(pattern, src, flags=re.MULTILINE)

if len(matches) != 1:
    raise SystemExit(
        "Error: expected exactly one wmchar_data anchor "
        f"in ntuser.h; found {len(matches)}"
    )

replacement = (
    r'\1'
    '    BOOL          thread_detached;  '
    '/* thread cleanup already performed */\n'
)

patched, count = re.subn(
    pattern,
    replacement,
    src,
    count=1,
    flags=re.MULTILINE,
)

if count != 1:
    raise SystemExit(
        "Error: failed to inject thread_detached into ntuser.h"
    )

dst.write_text(patched)
PYNTUSER


python3 - "$USER32_MAIN_FILE" "$USER32_MAIN_TMP" <<'PYUSER32'
from pathlib import Path
import re
import sys

src = Path(sys.argv[1]).read_text()
dst = Path(sys.argv[2])

if "thread_detached" in src:
    raise SystemExit(
        "Error: thread_detached already present in user_main.c"
    )

pattern = (
    r'(static void thread_detach\(void\)\n'
    r'\{\n'
    r'[ \t]*struct ntuser_thread_info \*thread_info = '
    r'NtUserGetThreadInfo\(\);\n'
    r'\n)'
    r'([ \t]*NtUserCallNoParam\( NtUserExitingThread \);\n)'
)

matches = re.findall(pattern, src)

if len(matches) != 1:
    raise SystemExit(
        "Error: expected exactly one user32 thread_detach "
        f"anchor; found {len(matches)}"
    )

replacement = (
    r'\1'
    '    if (thread_info->thread_detached) return;\n'
    '    thread_info->thread_detached = TRUE;\n'
    '\n'
    r'\2'
)

patched, count = re.subn(
    pattern,
    replacement,
    src,
    count=1,
)

if count != 1:
    raise SystemExit(
        "Error: failed to inject user32 thread detach guard"
    )

dst.write_text(patched)
PYUSER32


cp "$PROTOCOL_FILE" "$PROTOCOL_TMP"

cat >> "$PROTOCOL_TMP" <<'EOF'

@REQ(set_faketime)
    unsigned __int64 faketime;
@REPLY
@END
EOF

awk '
    /^#include "wine\/debug\.h"$/ {
    print
    print "#include \"linuwux_hooks.h\""
    print ""
    next
}

/^#ifdef HAVE_SECCOMP$/ {
    in_legacy_sigsys = 1
    print
    next
}

in_legacy_sigsys && /^#endif$/ {
    in_legacy_sigsys = 0
    print
    next
}

/^#if defined\(__APPLE__\) \|\| defined\(__linux__\)$/ {
    in_modern_sigsys = 1
    print
    next
}

in_modern_sigsys && /^#endif$/ {
    in_modern_sigsys = 0
    print
    next
}

in_legacy_sigsys &&
/TRACE_\(seh\)\("SIGSYS, rax/ {
    print "    if (linuwux_handle_sigsys(sigcontext))"
    print "        return;"
    print ""
}

in_modern_sigsys &&
/TRACE_\(seh\)\("SIGSYS, rax/ {
    print "    if (linuwux_handle_sigsys(sigcontext))"
    print "    {"
    print "        leave_handler(ucontext);"
    print "        return;"
    print "    }"
    print ""
}

/^static void segv_handler\( int signal, siginfo_t \*siginfo, void \*sigcontext \)$/ {
    in_segv = 1
    print
    next
}

in_segv && /^}$/ {
    in_segv = 0
    print
    next
}

in_segv && /rec\.ExceptionAddress = \(void \*\)RIP_sig\(ucontext\);/ {
    print "    if (linuwux_handle_cpuid(siginfo, ucontext))"
    print "        return;"
    print ""
}

    /if \(sigaction\( SIGSEGV, &sig_act, NULL \) == -1\) goto error;/ {
        print
        print "    detect_cpu_vendor();"
        print "    linuwux_prepare_kuser_write_alias();"
        print "    linuwux_debug_init();"
        print "    syscall(SYS_arch_prctl, ARCH_SET_CPUID, 0);"
        next
    }

    { print }
' "$SIGNAL_FILE" > "$SIGNAL_TMP"

if [[ "$LINUWUX_SYSCALL_BACKEND" == "sud" ]]
then
    python3 "$BPF_HELPER" "$SIGNAL_TMP"
fi

awk '
    /^timeout_t monotonic_time;$/ {
        print
        print "static timeout_t faketime = 0;"
        next
    }

    /current_time = \(timeout_t\)now\.tv_sec \* TICKS_PER_SEC \+ now\.tv_usec \* 10 \+ ticks_1601_to_1970;/ {
        sub(/;$/, " - faketime;")
        print
        next
    }

    { print }
' "$FD_FILE" > "$FD_TMP"

cat >> "$FD_TMP" <<'EOF'

DECL_HANDLER(set_faketime)
{
    faketime = ((current_time >> 32) - req->faketime) << 32;
}
EOF

cp "$WINE_INF_FILE" "$WINE_INF_TMP"

cat >> "$WINE_INF_TMP" <<'EOF'
HKLM,System\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001,"HwProfileGuid",,"{12345678-1234-1234-1234-123456789012}"
EOF

awk '
    /^                "winebth.sys": "d", #disable winebth.sys as it crashes winedevice.exe$/ {
        print
        print "                \"winmm\": \"n,b\","
        print "                \"version.dll\": \"n,b\","
        print "                \"reflex.dll\": \"n,b\","
        print "                \"d3d9\": \"n,b\","
        print "                \"d3d10\": \"n,b\","
        print "                \"d3d11\": \"n,b\","
        print "                \"d3d12\": \"n,b\","
        print "                \"dinput8\": \"n,b\","
        print "                \"dsound\": \"n,b\","
        print "                \"dxgi\": \"n,b\","
        print "                \"hid\": \"n,b\","
        print "                \"wininet\": \"n,b\","
        print "                \"winhttp\": \"n,b\","
        next
    }

    /^        # CW Bug 21737. Locoland executable happens to be steam.exe.$/ {
        print "        if \"PROTON_DISABLE_LSTEAMCLIENT\" not in os.environ:"
        print "            os.environ[\"PROTON_DISABLE_LSTEAMCLIENT\"] = \"1\""
        print "            self.env[\"PROTON_DISABLE_LSTEAMCLIENT\"] = \"1\""
        print ""
        print
        next
    }

    { print }
' "$PROTON_FILE" > "$PROTON_TMP"

if ! grep -Fq '"winmm": "n,b",' "$PROTON_TMP"
then
    echo "Error: failed to prepare winmm override in proton" >&2
    exit 1
fi

if ! grep -Fq '"version.dll": "n,b",' "$PROTON_TMP"
then
    echo "Error: failed to prepare version.dll override in proton" >&2
    exit 1
fi

if ! grep -Fq '"reflex.dll": "n,b",' "$PROTON_TMP"
then
    echo "Error: failed to prepare reflex.dll override in proton" >&2
    exit 1
fi

for LINUWUX_DLL_OVERRIDE in d3d9 d3d10 d3d11 d3d12 dinput8 dsound dxgi hid wininet winhttp
do
    if ! grep -Fq "\"${LINUWUX_DLL_OVERRIDE}\": \"n,b\"," "$PROTON_TMP"
    then
        echo "Error: failed to prepare ${LINUWUX_DLL_OVERRIDE} override in proton" >&2
        exit 1
    fi
done

if ! grep -Fq 'if "PROTON_DISABLE_LSTEAMCLIENT" not in os.environ:' "$PROTON_TMP"
then
    echo "Error: failed to prepare PROTON_DISABLE_LSTEAMCLIENT guard in proton" >&2
    exit 1
fi

if ! grep -Fq 'os.environ["PROTON_DISABLE_LSTEAMCLIENT"] = "1"' "$PROTON_TMP"
then
    echo "Error: failed to prepare PROTON_DISABLE_LSTEAMCLIENT os.environ value in proton" >&2
    exit 1
fi

if ! grep -Fq 'self.env["PROTON_DISABLE_LSTEAMCLIENT"] = "1"' "$PROTON_TMP"
then
    echo "Error: failed to prepare PROTON_DISABLE_LSTEAMCLIENT self.env value in proton" >&2
    exit 1
fi

if ! grep -Fq 'HKLM,System\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001,"HwProfileGuid",,"{12345678-1234-1234-1234-123456789012}"' "$WINE_INF_TMP"
then
    echo "Error: failed to prepare HwProfileGuid in wine.inf.in" >&2
    exit 1
fi

if ! grep -Fq 'static timeout_t faketime = 0;' "$FD_TMP"
then
    echo "Error: failed to prepare faketime state in fd.c" >&2
    exit 1
fi

if ! grep -Fq 'current_time = (timeout_t)now.tv_sec * TICKS_PER_SEC + now.tv_usec * 10 + ticks_1601_to_1970 - faketime;' "$FD_TMP"
then
    echo "Error: failed to prepare faketime-adjusted current_time in fd.c" >&2
    exit 1
fi

if ! grep -Fq 'DECL_HANDLER(set_faketime)' "$FD_TMP"
then
    echo "Error: failed to prepare set_faketime handler in fd.c" >&2
    exit 1
fi

if ! grep -Fq 'faketime = ((current_time >> 32) - req->faketime) << 32;' "$FD_TMP"
then
    echo "Error: failed to prepare set_faketime calculation in fd.c" >&2
    exit 1
fi

if [[ "$(grep -Fc 'BOOL          thread_detached;  /* thread cleanup already performed */' "$NTUSER_TMP" || true)" -ne 1 ]]
then
    echo "Error: failed to prepare thread_detached state in ntuser.h" >&2
    exit 1
fi

if [[ "$(grep -Fc 'if (thread_info->thread_detached) return;' "$USER32_MAIN_TMP" || true)" -ne 1 ]]
then
    echo "Error: failed to prepare user32 thread detach guard" >&2
    exit 1
fi

if [[ "$(grep -Fc 'thread_info->thread_detached = TRUE;' "$USER32_MAIN_TMP" || true)" -ne 1 ]]
then
    echo "Error: failed to prepare user32 thread detach state update" >&2
    exit 1
fi

if ! grep -Fq '@REQ(set_faketime)' "$PROTOCOL_TMP"
then
    echo "Error: failed to prepare set_faketime in protocol.def" >&2
    exit 1
fi

if ! grep -Fq '#include "linuwux_hooks.h"' "$SIGNAL_TMP"
then
    echo "Error: failed to prepare LinUwUx hooks in signal_x86_64.c" >&2
    exit 1
fi

cp "$PROTOCOL_TMP" "$PROTOCOL_FILE"
cp "$FD_TMP" "$FD_FILE"
cp "$WINE_INF_TMP" "$WINE_INF_FILE"
cp "$PROTON_TMP" "$PROTON_FILE"
cp "$SIGNAL_TMP" "$SIGNAL_FILE"
cp -p "$VIRTUAL_TMP" "$VIRTUAL_FILE"
cp -p "$UNIX_PRIVATE_TMP" "$UNIX_PRIVATE_FILE"
cp -p "$NTUSER_TMP" "$NTUSER_FILE"
cp -p "$USER32_MAIN_TMP" "$USER32_MAIN_FILE"
cp "$HOOKS_SOURCE" "$HOOKS_DEST"

# server/protocol.def is the authoritative Wine server protocol source.
# Regenerate its derived files instead of relying on potentially stale
# committed generated headers from a particular Wine/Proton backend.
if ! (
    cd "$SOURCE_DIR/wine"
    perl tools/make_requests
)
then
    echo "Error: failed to regenerate Wine server protocol files" >&2
    exit 1
fi

if ! grep -Fq 'struct set_faketime_request' "$SOURCE_DIR/wine/include/wine/server_protocol.h"
then
    echo "Error: generated server_protocol.h is missing set_faketime" >&2
    exit 1
fi

if ! grep -Fq 'REQ_set_faketime' "$SOURCE_DIR/wine/include/wine/server_protocol.h"
then
    echo "Error: generated server protocol request table is missing set_faketime" >&2
    exit 1
fi

if ! grep -Fq 'DECL_HANDLER(set_faketime);' "$SOURCE_DIR/wine/server/request_handlers.h"
then
    echo "Error: generated request_handlers.h is missing set_faketime" >&2
    exit 1
fi
