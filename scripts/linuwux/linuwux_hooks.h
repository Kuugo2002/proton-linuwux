/*
 * LinUwUx hooks for Wine ntdll Unix signal handling.
 *
 * Original LinUwUx patch by LinUwUx.
 * Robustness and compatibility rework by xshaduwulfx
 * for the Proton LinUwUx project.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef LINUWUX_HOOKS_INCLUDED
#define LINUWUX_HOOKS_INCLUDED

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#ifndef ARCH_SET_CPUID
#define ARCH_SET_CPUID 0x1012
#endif

enum linuwux_protocol_flag
{
    LINUWUX_PROTOCOL_CURRENT         = 1u << 0,
    LINUWUX_PROTOCOL_LEGACY          = 1u << 1,
    LINUWUX_PROTOCOL_LEGACY_OBSERVED = 1u << 2,
};

static unsigned int linuwux_protocol_flags;

struct linuwux_syscall_route
{
    uint64_t target;
    uint32_t syscall_id;
    unsigned int target_valid;
    unsigned int syscall_id_valid;
};

struct linuwux_syscall_router
{
    uint64_t generic_target;

    uint64_t pending_336933_target;
    unsigned int pending_336933_valid;

    struct linuwux_syscall_route qsi;
    struct linuwux_syscall_route qfa;
};

static struct linuwux_syscall_router linuwux_router;
static KUSER_SHARED_DATA *linuwux_kuser_write_alias;

/*
 * Optional diagnostics.
 *
 * Initialization happens outside signal context.  Signal-path diagnostics
 * use write(2) only and never influence protocol or routing decisions.
 */
static volatile sig_atomic_t linuwux_debug_enabled;
static int linuwux_debug_log_fd = -1;

static inline void linuwux_debug_emit(const char *message, size_t length)
{
    int saved_errno;

    if (!linuwux_debug_enabled || !length)
        return;

    saved_errno = errno;

    if (linuwux_debug_log_fd >= 0)
        (void)write(linuwux_debug_log_fd, message, length);

    (void)write(STDERR_FILENO, message, length);

    errno = saved_errno;
}

static void linuwux_debug_init(void)
{
    const char *value = getenv("LINUWUX_DEBUG");
    const char *path;
    int saved_errno = errno;

    linuwux_debug_enabled =
        value && value[0] == '1' && value[1] == '\0';

    if (!linuwux_debug_enabled)
    {
        errno = saved_errno;
        return;
    }

    path = getenv("LINUWUX_LOG");

    if (path && path[0] != '\0')
    {
        static const char enabled_message[] =
            "LinUwUx DEBUG [init] file logging enabled\n";
        static const char failed_message[] =
            "LinUwUx DEBUG [init] file logging unavailable\n";

        linuwux_debug_log_fd =
            open(path, O_WRONLY | O_CREAT | O_APPEND |
                       O_CLOEXEC | O_NOFOLLOW, 0600);

        if (linuwux_debug_log_fd >= 0)
            linuwux_debug_emit(enabled_message,
                               sizeof(enabled_message) - 1);
        else
            linuwux_debug_emit(failed_message,
                               sizeof(failed_message) - 1);
    }

    {
        static const char message[] =
            "LinUwUx DEBUG [init] enabled\n";

        linuwux_debug_emit(message, sizeof(message) - 1);
    }

    errno = saved_errno;
}

static inline void linuwux_debug_event(const char *message, size_t length)
{
    linuwux_debug_emit(message, length);
}

#define LINUWUX_DEBUG_OBS_MAX 32

/*
 * Fixed-size, signal-safe diagnostic deduplication table.
 *
 * Each observation is reduced to a non-zero 32-bit fingerprint derived
 * from its type and values. Slots are claimed atomically so concurrent
 * signal handlers cannot race on partially-written observation records.
 *
 * Once the bounded table is full, further diagnostic observations are
 * silently suppressed. Diagnostics must never influence runtime behavior.
 */
static unsigned int
    linuwux_debug_observation_fingerprints[LINUWUX_DEBUG_OBS_MAX];

static inline uint32_t linuwux_debug_hash_byte(uint32_t hash,
                                               unsigned char value)
{
    hash ^= value;
    hash *= UINT32_C(16777619);
    return hash;
}

static inline uint32_t linuwux_debug_observation_fingerprint(
    const char *type, uint64_t value1, uint64_t value2)
{
    uint32_t hash = UINT32_C(2166136261);
    unsigned int i;

    while (*type)
        hash = linuwux_debug_hash_byte(hash, (unsigned char)*type++);

    for (i = 0; i < 8; ++i)
    {
        hash = linuwux_debug_hash_byte(hash, (unsigned char)value1);
        value1 >>= 8;
    }

    for (i = 0; i < 8; ++i)
    {
        hash = linuwux_debug_hash_byte(hash, (unsigned char)value2);
        value2 >>= 8;
    }

    /* Zero means an unused slot. */
    if (!hash)
        hash = 1;

    return hash;
}

static inline int linuwux_debug_observation_seen(const char *type,
                                                 uint64_t value1,
                                                 uint64_t value2)
{
    uint32_t fingerprint =
        linuwux_debug_observation_fingerprint(type, value1, value2);
    unsigned int i;

    for (i = 0; i < LINUWUX_DEBUG_OBS_MAX; ++i)
    {
        unsigned int observed = __atomic_load_n(
            &linuwux_debug_observation_fingerprints[i],
            __ATOMIC_RELAXED);

        if (observed == fingerprint)
            return 1;

        if (!observed)
        {
            unsigned int expected = 0;

            if (__atomic_compare_exchange_n(
                    &linuwux_debug_observation_fingerprints[i],
                    &expected,
                    fingerprint,
                    0,
                    __ATOMIC_RELAXED,
                    __ATOMIC_RELAXED))
                return 0;

            if (expected == fingerprint)
                return 1;
        }
    }

    return 1;
}

static inline char *linuwux_debug_append_hex64(char *p, uint64_t value)
{
    static const char hex[] = "0123456789abcdef";
    int shift;

    *p++ = '0';
    *p++ = 'x';

    for (shift = 60; shift >= 0; shift -= 4)
        *p++ = hex[(value >> shift) & 0xf];

    return p;
}

static inline void linuwux_debug_observation(const char *type,
                                             uint64_t value1,
                                             uint64_t value2)
{
    char buffer[192];
    char *p = buffer;
    const char *s;
    int saved_errno;

    if (!linuwux_debug_enabled)
        return;

    if (linuwux_debug_observation_seen(type, value1, value2))
        return;

    saved_errno = errno;

    for (s = "LinUwUx DEBUG [observation] "; *s; ++s)
        *p++ = *s;

    for (s = type; *s && p < buffer + sizeof(buffer) - 64; ++s)
        *p++ = *s;

    for (s = " value1="; *s; ++s)
        *p++ = *s;

    p = linuwux_debug_append_hex64(p, value1);

    for (s = " value2="; *s; ++s)
        *p++ = *s;

    p = linuwux_debug_append_hex64(p, value2);
    *p++ = '\n';

    linuwux_debug_emit(buffer, p - buffer);

    errno = saved_errno;
}

#define LINUWUX_DEBUG_EVENT(message) \
    linuwux_debug_event((message), sizeof(message) - 1)

uint64_t SyscallBypassMagic = 0x1337133713371337;

/* Spoofed CPUID values - set based on CPU vendor. */
static unsigned int spoof_leaf40000000_eax;
static unsigned int spoof_leaf40000000_ebx;
static unsigned int spoof_leaf40000000_ecx;
static unsigned int spoof_leaf40000000_edx;

static unsigned int spoof_leaf40000001_eax;
static unsigned int spoof_leaf40000001_ebx;
static unsigned int spoof_leaf40000001_ecx;
static unsigned int spoof_leaf40000001_edx;

static unsigned int spoof_leaf1_eax;
static unsigned int spoof_leaf1_ebx;
static unsigned int spoof_leaf1_ecx;
static unsigned int spoof_leaf1_edx;

enum linuwux_cpu_vendor
{
    LINUWUX_CPU_VENDOR_UNKNOWN,
    LINUWUX_CPU_VENDOR_INTEL,
    LINUWUX_CPU_VENDOR_AMD
};

static enum linuwux_cpu_vendor linuwux_host_cpu_vendor =
    LINUWUX_CPU_VENDOR_UNKNOWN;

/**
 * Patch KUSER_SHARED_DATA with spoofed values.
 */
struct linuwux_kuser_saved_region
{
    size_t offset;
    size_t size;
    UINT8 *data;
};

static UINT8 linuwux_saved_kuser_0030[0x16];
static UINT8 linuwux_saved_kuser_0260[0x54];
static UINT8 linuwux_saved_kuser_02d0[0x08];
static UINT8 linuwux_saved_kuser_02e8[0x08];
static UINT8 linuwux_saved_kuser_02f4[0x04];
static UINT8 linuwux_saved_kuser_036c[0x14];
static UINT8 linuwux_saved_kuser_03c0[0x08];
static UINT8 linuwux_saved_kuser_03d8[0x10];
static UINT8 linuwux_saved_kuser_03ec[0x204];
static UINT8 linuwux_saved_kuser_05f0[0x10];
static UINT8 linuwux_saved_kuser_0604[0x200];
static UINT8 linuwux_saved_kuser_0808[0x10];
static UINT8 linuwux_saved_kuser_0ffc[0x04];

static struct linuwux_kuser_saved_region linuwux_current_kuser_regions[] =
{
    {0x030, sizeof(linuwux_saved_kuser_0030), linuwux_saved_kuser_0030},
    {0x260, sizeof(linuwux_saved_kuser_0260), linuwux_saved_kuser_0260},
    {0x2d0, sizeof(linuwux_saved_kuser_02d0), linuwux_saved_kuser_02d0},
    {0x2e8, sizeof(linuwux_saved_kuser_02e8), linuwux_saved_kuser_02e8},
    {0x2f4, sizeof(linuwux_saved_kuser_02f4), linuwux_saved_kuser_02f4},
    {0x36c, sizeof(linuwux_saved_kuser_036c), linuwux_saved_kuser_036c},
    {0x3c0, sizeof(linuwux_saved_kuser_03c0), linuwux_saved_kuser_03c0},
    {0x3d8, sizeof(linuwux_saved_kuser_03d8), linuwux_saved_kuser_03d8},
    {0x3ec, sizeof(linuwux_saved_kuser_03ec), linuwux_saved_kuser_03ec},
    {0x5f0, sizeof(linuwux_saved_kuser_05f0), linuwux_saved_kuser_05f0},
    {0x604, sizeof(linuwux_saved_kuser_0604), linuwux_saved_kuser_0604},
    {0x808, sizeof(linuwux_saved_kuser_0808), linuwux_saved_kuser_0808},
    {0xffc, sizeof(linuwux_saved_kuser_0ffc), linuwux_saved_kuser_0ffc},
};

static int linuwux_current_kuser_snapshot_valid;

static void linuwux_snapshot_current_kuser_state(void)
{
    UINT8 *kuser = (UINT8 *)0x000000007FFE0000UL;
    size_t i;

    if (linuwux_current_kuser_snapshot_valid)
        return;

    for (i = 0; i < sizeof(linuwux_current_kuser_regions) /
                    sizeof(linuwux_current_kuser_regions[0]); ++i)
    {
        memcpy(linuwux_current_kuser_regions[i].data,
               kuser + linuwux_current_kuser_regions[i].offset,
               linuwux_current_kuser_regions[i].size);
    }

    linuwux_current_kuser_snapshot_valid = 1;
    LINUWUX_DEBUG_EVENT("LinUwUx DEBUG [kuser] current snapshot saved\n");
}

static void linuwux_restore_pre_current_kuser_state(void)
{
    UINT8 *kuser = (UINT8 *)0x000000007FFE0000UL;
    long page_size_result;
    size_t page_size;
    void *page_start;
    size_t i;

    if (!linuwux_current_kuser_snapshot_valid)
        return;

    page_size_result = sysconf(_SC_PAGESIZE);
    if (page_size_result == -1)
        linuwux_debug_observation(
            "kuser-page-size-query-failed",
            UINT64_C(1),
            (uint64_t)errno);

    page_size = (size_t)page_size_result;
    page_start =
        (void *)((uintptr_t)0x000000007FFE0000UL & ~(page_size - 1));

    if (mprotect(page_start, page_size, PROT_READ | PROT_WRITE) == -1)
    {
        int call_errno = errno;

        linuwux_debug_observation(
            "kuser-mprotect-failed",
            UINT64_C(1),
            (uint64_t)call_errno);

        MESSAGE("Failed to restore pre-current KUSER state: %s\n",
                strerror(call_errno));
        return;
    }

    for (i = 0; i < sizeof(linuwux_current_kuser_regions) /
                    sizeof(linuwux_current_kuser_regions[0]); ++i)
    {
        memcpy(kuser + linuwux_current_kuser_regions[i].offset,
               linuwux_current_kuser_regions[i].data,
               linuwux_current_kuser_regions[i].size);
    }

    linuwux_current_kuser_snapshot_valid = 0;
    LINUWUX_DEBUG_EVENT("LinUwUx DEBUG [kuser] pre-current state restored\n");
}

static void patch_kuser_shared_data(void)
{
    UINT8 *kuser = (UINT8 *)0x000000007FFE0000UL;

    /* Make memory writable. */
    long page_size_result = sysconf(_SC_PAGESIZE);
    size_t page_size;
    void *page_start;

    if (page_size_result == -1)
        linuwux_debug_observation(
            "kuser-page-size-query-failed",
            UINT64_C(2),
            (uint64_t)errno);

    page_size = (size_t)page_size_result;
    page_start =
        (void *)((uintptr_t)0x000000007FFE0000UL & ~(page_size - 1));

    if (mprotect(page_start, page_size, PROT_READ | PROT_WRITE) == -1)
    {
        int call_errno = errno;

        linuwux_debug_observation(
            "kuser-mprotect-failed",
            UINT64_C(2),
            (uint64_t)call_errno);

        MESSAGE("Failed to make kuser_shared_data writable: %s\n",
                strerror(call_errno));
        return;
    }

    linuwux_snapshot_current_kuser_state();

    memcpy((void *)(kuser + 0x30),
           "\x43\x00\x3a\x00\x5c\x00\x57\x00\x69\x00\x6e\x00"
           "\x64\x00\x6f\x00\x77\x00\x73\x00\x00\x00",
           0x16);

    *(UINT64 *)(kuser + 0x260) = 0x0100006658;
    *(UINT32 *)(kuser + 0x268) = 0x090001;
    *(UINT32 *)(kuser + 0x26C) = 0x0A;
    *(UINT32 *)(kuser + 0x270) = 0x00;

    /* ProcessorFeatures */
    *(UINT32 *)(kuser + 0x274) = 0x01010000;
    *(UINT32 *)(kuser + 0x278) = 0x010000;
    *(UINT32 *)(kuser + 0x27C) = 0x010101;
    *(UINT32 *)(kuser + 0x280) = 0x010101;
    *(UINT32 *)(kuser + 0x284) = 0x0100;
    *(UINT32 *)(kuser + 0x288) = 0x01010101;
    *(UINT32 *)(kuser + 0x28C) = 0x0;
    *(UINT32 *)(kuser + 0x290) = 0x01;
    *(UINT32 *)(kuser + 0x294) = 0x01000101;
    *(UINT32 *)(kuser + 0x298) = 0x01010101;
    *(UINT32 *)(kuser + 0x29C) = 0x010001;
    *(UINT32 *)(kuser + 0x2A0) = 0x0;
    *(UINT32 *)(kuser + 0x2A4) = 0x0;
    *(UINT32 *)(kuser + 0x2A8) = 0x0;
    *(UINT32 *)(kuser + 0x2AC) = 0x0;
    *(UINT32 *)(kuser + 0x2B0) = 0x1;

    /* Disable specific features (byte-level patches). */
    *(UINT8 *)(kuser + 0x290) = 0x0; /* Disable MONITORX support */
    *(UINT8 *)(kuser + 0x294) = 0x0; /* Disable RDTSCP support */
    *(UINT8 *)(kuser + 0x295) = 0x0; /* Disable RDPID support */
    *(UINT8 *)(kuser + 0x297) = 0x0; /* Disable RDRAND support */

    if (getenv("PROTON_AVX") == NULL ||
        (getenv("PROTON_AVX") != NULL && strcmp(getenv("PROTON_AVX"), "1")) != 0)
    {
        /* XSAVE related stuff */
        *(UINT8 *)(kuser + 0x285) = 0x0; /* Disable XSAVE support */
        *(UINT8 *)(kuser + 0x29B) = 0x0; /* Disable AVX support */
        *(UINT8 *)(kuser + 0x29C) = 0x0; /* Disable AVX2 support */
    }

    *(UINT64 *)(kuser + 0x3D8) = 0x0; /* EnabledFeatures */
    *(UINT64 *)(kuser + 0x3E0) = 0x0; /* EnabledVolatileFeatures */
    *(UINT32 *)(kuser + 0x3EC) = 0x0; /* ControlFlags */
    memset((void *)(kuser + 0x3F0), 0x00, 0x200); /* Features */
    *(UINT64 *)(kuser + 0x5F0) = 0x0; /* EnabledSupervisorFeatures */
    *(UINT64 *)(kuser + 0x5F8) = 0x0; /* AlignedFeatures */
    memset((void *)(kuser + 0x604), 0x00, 0x200); /* AllFeatures */
    *(UINT64 *)(kuser + 0x808) = 0x0; /* EnabledUserVisibleSupervisorFeatures */
    *(UINT64 *)(kuser + 0x810) = 0x0; /* ExtendedFeatureDisableFeatures */

    *(UINT64 *)(kuser + 0x2D0) = 0x320A0000000110;
    *(UINT64 *)(kuser + 0x2E8) = 0x0100007FB10B;
    *(UINT32 *)(kuser + 0x2F4) = 0x0;
    *(UINT64 *)(kuser + 0x36C) = 0x0;
    *(UINT64 *)(kuser + 0x374) = 0x0;
    *(UINT32 *)(kuser + 0x37C) = 0x1;
    *(UINT64 *)(kuser + 0x3C0) = 0x83000100000010;

    *(UINT32 *)(kuser + 0xFFC) = 0x13371337;

    LINUWUX_DEBUG_EVENT("LinUwUx DEBUG [kuser] current profile applied\n");

    /* Patch usage of syscalls:
     * 0 = syscalls take slow route, everything gets hooked
     * 1 = syscalls take fast route unless ntdll.dll gets modified (default)
     */
    /* kuser[0x308] = 1; */
}

static void linuwux_prepare_kuser_write_alias(void)
{
    if (linuwux_kuser_write_alias)
        return;

    linuwux_kuser_write_alias =
        virtual_map_user_shared_data_write_alias();

    if (!linuwux_kuser_write_alias)
        MESSAGE("LinUwUx: writable KUSER alias unavailable\n");
}

/**
 * Force Wine x86-64 syscall thunks through the syscall instruction path.
 *
 * Keep this separate from the visible-state profiles because known
 * protocol variants differ in whether they request the slow route.
 */
static inline void linuwux_enable_syscall_slow_route(void)
{
    if (linuwux_kuser_write_alias)
    {
        linuwux_kuser_write_alias->SystemCall = 0;
        LINUWUX_DEBUG_EVENT("LinUwUx DEBUG [syscall] slow route enabled\n");
    }
}

/**
 * Apply the common legacy KUSER_SHARED_DATA visible-state profile.
 *
 * Keep syscall-route selection separate: known legacy variants differ
 * in whether they force KUSER_SHARED_DATA.SystemCall to the slow route.
 */
static void patch_legacy_kuser_shared_data(void)
{
    UINT8 *kuser = (UINT8 *)0x000000007FFE0000UL;
    long page_size_result = sysconf(_SC_PAGESIZE);
    size_t page_size;
    void *page_start;

    if (page_size_result == -1)
        linuwux_debug_observation(
            "kuser-page-size-query-failed",
            UINT64_C(3),
            (uint64_t)errno);

    page_size = (size_t)page_size_result;
    page_start =
        (void *)((uintptr_t)0x000000007FFE0000UL & ~(page_size - 1));

    static const UINT8 legacy_260_27a[] =
    {
        0x58, 0x66, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x09, 0x00, 0x0a, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
        0x00, 0x00, 0x01
    };

    static const UINT8 legacy_281_284[] =
    {
        0x01, 0x01, 0x00, 0x00
    };

    static const UINT8 legacy_286_28f[] =
    {
        0x00, 0x00, 0x01, 0x01, 0x01,
        0x01, 0x00, 0x00, 0x00, 0x00
    };

    if (mprotect(page_start, page_size, PROT_READ | PROT_WRITE) == -1)
    {
        int call_errno = errno;

        linuwux_debug_observation(
            "kuser-mprotect-failed",
            UINT64_C(3),
            (uint64_t)call_errno);

        MESSAGE("Failed to make legacy kuser_shared_data writable: %s\n",
                strerror(call_errno));
        return;
    }

    *(UINT64 *)(kuser + 0x000) = UINT64_C(0x0fa0000000000000);

    memcpy(kuser + 0x260, legacy_260_27a, sizeof(legacy_260_27a));
    memcpy(kuser + 0x281, legacy_281_284, sizeof(legacy_281_284));
    memcpy(kuser + 0x286, legacy_286_28f, sizeof(legacy_286_28f));

    *(UINT64 *)(kuser + 0x2d0) = UINT64_C(0x00320a0000000110);
    *(UINT64 *)(kuser + 0x2e8) = UINT64_C(0x00000100007fb10b);
    *(UINT32 *)(kuser + 0x2f4) = UINT32_C(0);

    *(UINT64 *)(kuser + 0x378) = UINT64_C(0x0000000100000000);
    *(UINT64 *)(kuser + 0x3c0) = UINT64_C(0x0083000100000010);

    LINUWUX_DEBUG_EVENT("LinUwUx DEBUG [kuser] legacy profile applied\n");
}

/*
 * Detect the host CPU vendor and initialize spoofed CPUID values.
 */
static void detect_cpu_vendor(void)
{
    unsigned int eax, ebx, ecx, edx;
    int avx = 0;

    if (getenv("PROTON_AVX") != NULL &&
        strcmp(getenv("PROTON_AVX"), "1") == 0)
        avx = 1;

    __asm__ volatile(
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(0)
        : "memory"
    );

    if (ebx == 0x756E6547 && edx == 0x49656E69 && ecx == 0x6C65746E)
    {
        /* GenuineIntel */
        linuwux_host_cpu_vendor = LINUWUX_CPU_VENDOR_INTEL;
        spoof_leaf1_eax = 0x000A0655;
        spoof_leaf1_ebx = 0x00200800;

        if (avx)
            spoof_leaf1_ecx = 0x7BFAFBFF;
        else
            spoof_leaf1_ecx = 0x01FAEBFF;

        spoof_leaf1_edx = 0xBFEBFBFF;

        spoof_leaf40000000_eax = 0x40000001;
        spoof_leaf40000000_ebx = 0x65707948;
        spoof_leaf40000000_ecx = 0x67624472;
        spoof_leaf40000000_edx = 0;

        spoof_leaf40000001_eax = 0x30237648;
        spoof_leaf40000001_ebx = 0;
        spoof_leaf40000001_ecx = 0;
        spoof_leaf40000001_edx = 0;
    }
    else if (ebx == 0x68747541 && edx == 0x69746E65 && ecx == 0x444D4163)
    {
        /* AuthenticAMD */
        linuwux_host_cpu_vendor = LINUWUX_CPU_VENDOR_AMD;
        spoof_leaf1_eax = 0x00A20F12;
        spoof_leaf1_ebx = 0x00100800;

        if (avx)
            spoof_leaf1_ecx = 0x7AD8320B;
        else
            spoof_leaf1_ecx = 0x00F8220B;

        spoof_leaf1_edx = 0x178BFBFF;

        spoof_leaf40000000_eax = 0x40000001;
        spoof_leaf40000000_ebx = 0x706D6953;
        spoof_leaf40000000_ecx = 0x7653656C;
        spoof_leaf40000000_edx = 0x2020206D;

        spoof_leaf40000001_eax = 0x30237648;
        spoof_leaf40000001_ebx = 0;
        spoof_leaf40000001_ecx = 0;
        spoof_leaf40000001_edx = 0;
    }

    /* Sorry Zhaoxin/Hygon CPU owners :( */
}

static void linuwux_zero_cpuid_result(ucontext_t *ucontext)
{
    ucontext->uc_mcontext.gregs[REG_RAX] = 0;
    ucontext->uc_mcontext.gregs[REG_RBX] = 0;
    ucontext->uc_mcontext.gregs[REG_RCX] = 0;
    ucontext->uc_mcontext.gregs[REG_RDX] = 0;
}

static inline void linuwux_commit_pending_current_route(void)
{
    if (!linuwux_router.pending_336933_valid)
        return;

    if (linuwux_protocol_flags & LINUWUX_PROTOCOL_LEGACY)
        return;

    linuwux_protocol_flags |= LINUWUX_PROTOCOL_CURRENT;

    linuwux_router.generic_target =
        linuwux_router.pending_336933_target;

    linuwux_router.pending_336933_target = 0;
    linuwux_router.pending_336933_valid = 0;

    LINUWUX_DEBUG_EVENT("LinUwUx DEBUG [router] pending -> current\n");
}


static inline void linuwux_resolve_pending_legacy_route(void)
{
    if (!linuwux_router.pending_336933_valid)
        return;

    if (!linuwux_router.qsi.target_valid)
    {
        linuwux_router.qsi.target =
            linuwux_router.pending_336933_target;
        linuwux_router.qsi.target_valid = 1;
    }

    linuwux_router.pending_336933_target = 0;
    linuwux_router.pending_336933_valid = 0;

    LINUWUX_DEBUG_EVENT("LinUwUx DEBUG [router] pending -> legacy QSI\n");
}


static void linuwux_activate_legacy_protocol(void)
{
    unsigned int was_legacy =
        linuwux_protocol_flags & LINUWUX_PROTOCOL_LEGACY;

    linuwux_protocol_flags |= LINUWUX_PROTOCOL_LEGACY;

    if (linuwux_router.pending_336933_valid)
    {
        linuwux_resolve_pending_legacy_route();
    }
    else if (!linuwux_router.qsi.target_valid &&
             linuwux_router.generic_target)
    {
        linuwux_router.qsi.target =
            linuwux_router.generic_target;
        linuwux_router.qsi.target_valid = 1;
    }

    /*
     * KUSER transition remains deferred until the existing explicit
     * legacy-profile event.
     */
    if (!was_legacy)
    {
        MESSAGE("Activating legacy LinUwUx protocol\n");
        LINUWUX_DEBUG_EVENT(
            "LinUwUx DEBUG [router] legacy activated\n");
    }
}

static int linuwux_apply_legacy_cpuid_profile(unsigned int leaf,
                                               ucontext_t *ucontext)
{
    if (!(linuwux_protocol_flags & LINUWUX_PROTOCOL_LEGACY))
        return 0;

    switch (leaf)
    {
        case 1:
            if (linuwux_host_cpu_vendor == LINUWUX_CPU_VENDOR_INTEL)
            {
                ucontext->uc_mcontext.gregs[REG_RAX] = 0x000a0655;
                ucontext->uc_mcontext.gregs[REG_RBX] = 0x00200800;
                ucontext->uc_mcontext.gregs[REG_RCX] = 0x7bfafbff;
                ucontext->uc_mcontext.gregs[REG_RDX] = 0xbfebfbff;
            }
            else
            {
                ucontext->uc_mcontext.gregs[REG_RAX] = 0x00a20f10;
                ucontext->uc_mcontext.gregs[REG_RBX] = 0x00180800;
                ucontext->uc_mcontext.gregs[REG_RCX] = 0x7ad8320b;
                ucontext->uc_mcontext.gregs[REG_RDX] =
                    linuwux_host_cpu_vendor == LINUWUX_CPU_VENDOR_AMD
                        ? 0x178bfbff
                        : 0x00000000;
            }
            return 1;

        case 0x80000002:
            if (linuwux_host_cpu_vendor == LINUWUX_CPU_VENDOR_INTEL)
            {
                ucontext->uc_mcontext.gregs[REG_RAX] = 0x65746e49;
                ucontext->uc_mcontext.gregs[REG_RBX] = 0x2952286c;
                ucontext->uc_mcontext.gregs[REG_RCX] = 0x726f4320;
                ucontext->uc_mcontext.gregs[REG_RDX] = 0x4d542865;
            }
            else
            {
                ucontext->uc_mcontext.gregs[REG_RAX] = 0x20444d41;
                ucontext->uc_mcontext.gregs[REG_RBX] = 0x657a7952;
                ucontext->uc_mcontext.gregs[REG_RCX] = 0x2039206e;
                ucontext->uc_mcontext.gregs[REG_RDX] = 0x30303935;
            }
            return 1;

        case 0x80000003:
            if (linuwux_host_cpu_vendor == LINUWUX_CPU_VENDOR_INTEL)
            {
                ucontext->uc_mcontext.gregs[REG_RAX] = 0x39692029;
                ucontext->uc_mcontext.gregs[REG_RBX] = 0x3930312d;
                ucontext->uc_mcontext.gregs[REG_RCX] = 0x204b3030;
                ucontext->uc_mcontext.gregs[REG_RDX] = 0x20555043;
            }
            else
            {
                ucontext->uc_mcontext.gregs[REG_RAX] = 0x32312058;
                ucontext->uc_mcontext.gregs[REG_RBX] = 0x726f432d;
                ucontext->uc_mcontext.gregs[REG_RCX] = 0x72502065;
                ucontext->uc_mcontext.gregs[REG_RDX] = 0x7365636f;
            }
            return 1;

        case 0x80000004:
            if (linuwux_host_cpu_vendor == LINUWUX_CPU_VENDOR_INTEL)
            {
                ucontext->uc_mcontext.gregs[REG_RAX] = 0x2e332040;
                ucontext->uc_mcontext.gregs[REG_RBX] = 0x48473037;
                ucontext->uc_mcontext.gregs[REG_RCX] = 0x2020207a;
                ucontext->uc_mcontext.gregs[REG_RDX] = 0x00202020;
            }
            else
            {
                ucontext->uc_mcontext.gregs[REG_RAX] = 0x20726f73;
                ucontext->uc_mcontext.gregs[REG_RBX] = 0x20202020;
                ucontext->uc_mcontext.gregs[REG_RCX] = 0x20202020;
                ucontext->uc_mcontext.gregs[REG_RDX] = 0x00202020;
            }
            return 1;

        default:
            return 0;
    }
}

static int linuwux_handle_cpuid(siginfo_t *siginfo, ucontext_t *ucontext)
{
    unsigned int leaf;
    unsigned int subleaf;
    unsigned char *rip;

    rip = (unsigned char *)ucontext->uc_mcontext.gregs[REG_RIP];
    leaf = ucontext->uc_mcontext.gregs[REG_RAX];
    subleaf = ucontext->uc_mcontext.gregs[REG_RCX];

    if ((siginfo->si_code == SI_KERNEL || leaf == 0x336933) &&
        rip[0] == 0x0f && rip[1] == 0xa2)
    {
        if (linuwux_apply_legacy_cpuid_profile(leaf, ucontext))
        {
            ucontext->uc_mcontext.gregs[REG_RIP] += 2;
            return 1;
        }

        switch (leaf)
        {
            case 1:
                ucontext->uc_mcontext.gregs[REG_RAX] = spoof_leaf1_eax;
                ucontext->uc_mcontext.gregs[REG_RBX] = spoof_leaf1_ebx;
                ucontext->uc_mcontext.gregs[REG_RCX] = spoof_leaf1_ecx;
                ucontext->uc_mcontext.gregs[REG_RDX] = spoof_leaf1_edx;
                break;

            case 0x40000000:
                ucontext->uc_mcontext.gregs[REG_RAX] = spoof_leaf40000000_eax;
                ucontext->uc_mcontext.gregs[REG_RBX] = spoof_leaf40000000_ebx;
                ucontext->uc_mcontext.gregs[REG_RCX] = spoof_leaf40000000_ecx;
                ucontext->uc_mcontext.gregs[REG_RDX] = spoof_leaf40000000_edx;
                break;

            case 0x40000001:
                ucontext->uc_mcontext.gregs[REG_RAX] = spoof_leaf40000001_eax;
                ucontext->uc_mcontext.gregs[REG_RBX] = spoof_leaf40000001_ebx;
                ucontext->uc_mcontext.gregs[REG_RCX] = spoof_leaf40000001_ecx;
                ucontext->uc_mcontext.gregs[REG_RDX] = spoof_leaf40000001_edx;
                break;

            case 0x80000002:
                ucontext->uc_mcontext.gregs[REG_RAX] = 0x756E6544;
                ucontext->uc_mcontext.gregs[REG_RBX] = 0x4F774F76;
                ucontext->uc_mcontext.gregs[REG_RCX] = 0x55504320;
                ucontext->uc_mcontext.gregs[REG_RDX] = 0x31204020;
                break;

            case 0x80000003:
                ucontext->uc_mcontext.gregs[REG_RAX] = 0x20373333;
                ucontext->uc_mcontext.gregs[REG_RBX] = 0x007A4847;
                ucontext->uc_mcontext.gregs[REG_RCX] = 0x00000000;
                ucontext->uc_mcontext.gregs[REG_RDX] = 0x00000000;
                break;

            case 0x80000004:
                linuwux_zero_cpuid_result(ucontext);
                break;

            case 0x336933:
                if (linuwux_protocol_flags & LINUWUX_PROTOCOL_LEGACY)
                {
                    MESSAGE("Registering legacy QSI syscall target\n");

                    linuwux_router.qsi.target =
                        ucontext->uc_mcontext.gregs[REG_RCX];
                    linuwux_router.qsi.target_valid = 1;
                }
                else if (linuwux_protocol_flags &
                         LINUWUX_PROTOCOL_LEGACY_OBSERVED)
                {
                    /*
                     * Ambiguous registration.
                     *
                     * Keep routing unresolved while exposing the CURRENT
                     * KUSER-visible state required by the syscall path.
                     * A later LEGACY promotion restores the pre-CURRENT
                     * snapshot before applying the legacy KUSER profile.
                     */
                    linuwux_router.pending_336933_target =
                        ucontext->uc_mcontext.gregs[REG_RCX];

                    linuwux_router.pending_336933_valid = 1;

                    LINUWUX_DEBUG_EVENT(
                        "LinUwUx DEBUG [router] pending 336933 registered\n");

                    /*
                     * Pending CURRENT-visible state.
                     *
                     * Routing remains unresolved until either an explicit
                     * legacy registration or the first routable SIGSYS.
                     * Snapshot support allows a later LEGACY transition to
                     * reconstruct its pre-CURRENT KUSER state.
                     */
                    patch_kuser_shared_data();
                    linuwux_enable_syscall_slow_route();
                }
                else
                {
                    /*
                     * Direct/non-ambiguous CURRENT path remains unchanged.
                     */
                    MESSAGE("Spoofing CPUID leaf %x\n", leaf);

                    linuwux_protocol_flags |=
                        LINUWUX_PROTOCOL_CURRENT;

                    linuwux_router.generic_target =
                        ucontext->uc_mcontext.gregs[REG_RCX];

                    patch_kuser_shared_data();
                    linuwux_enable_syscall_slow_route();
                }

                linuwux_zero_cpuid_result(ucontext);
                break;

            case 0x69696969:
                /*
                 * Observation only: no semantic protocol transition yet.
                 */
                MESSAGE("Observing legacy LinUwUx protocol\n");

                linuwux_protocol_flags |=
                    LINUWUX_PROTOCOL_LEGACY_OBSERVED;

                LINUWUX_DEBUG_EVENT(
                    "LinUwUx DEBUG [router] legacy observed\n");

                goto native_cpuid;

            case 0x336943:
                linuwux_activate_legacy_protocol();

                MESSAGE("Registering legacy QSI syscall ID\n");
                linuwux_router.qsi.syscall_id =
                    (uint32_t)ucontext->uc_mcontext.gregs[REG_RCX];
                linuwux_router.qsi.syscall_id_valid = 1;
                linuwux_zero_cpuid_result(ucontext);
                break;

            case 0x336934:
                linuwux_activate_legacy_protocol();

                MESSAGE("Registering legacy QFA syscall target\n");
                linuwux_router.qfa.target =
                    ucontext->uc_mcontext.gregs[REG_RCX];
                linuwux_router.qfa.target_valid = 1;
                linuwux_zero_cpuid_result(ucontext);
                break;

            case 0x336944:
                linuwux_activate_legacy_protocol();

                MESSAGE("Registering legacy QFA syscall ID\n");
                linuwux_router.qfa.syscall_id =
                    (uint32_t)ucontext->uc_mcontext.gregs[REG_RCX];
                linuwux_router.qfa.syscall_id_valid = 1;
                linuwux_zero_cpuid_result(ucontext);
                break;

            case 0x336967:
                MESSAGE("Setting Faketime to %llx... \n",
                        ucontext->uc_mcontext.gregs[REG_RCX]);
                SERVER_START_REQ( set_faketime )
                {
                    unsigned int status;

                    req->faketime = ucontext->uc_mcontext.gregs[REG_RCX];
                    status = wine_server_call( req );

                    if (status)
                        linuwux_debug_observation(
                            "faketime-server-call-failed",
                            (uint64_t)status,
                            UINT64_C(0));
                }
                SERVER_END_REQ;
                linuwux_zero_cpuid_result(ucontext);
                break;

            case 0x1337:
                if (linuwux_protocol_flags & LINUWUX_PROTOCOL_LEGACY)
                {
                    MESSAGE("Applying legacy KUSER_SHARED_DATA profile\n");

                    /*
                     * A retroactively promoted legacy session may already
                     * have received the CURRENT KUSER profile through
                     * 0x336933.  Reconstruct the state that historical
                     * legacy entry would have seen before applying its
                     * profile.
                     */
                    linuwux_restore_pre_current_kuser_state();
                    patch_legacy_kuser_shared_data();
                    linuwux_enable_syscall_slow_route();
                    linuwux_zero_cpuid_result(ucontext);
                    break;
                }

                /* Non-legacy callers retain the native CPUID result. */
                __attribute__((fallthrough));

            default:
                /*
                 * The historical LinUwUx protocol uses several CPUID
                 * control leaves in the 0x3369xx range.  Unknown values
                 * in that range are observational only: preserve native
                 * CPUID behavior while making new protocol-like inputs
                 * visible to optional diagnostics.
                 */
                if ((leaf & UINT64_C(0xffffff00)) ==
                    UINT64_C(0x336900))
                {
                    linuwux_debug_observation(
                        "unknown-3369-control-leaf",
                        leaf,
                        subleaf);
                }

native_cpuid:
                {
                    long result;
                    int call_errno;

                    result = syscall(SYS_arch_prctl, ARCH_SET_CPUID, 1);
                    call_errno = errno;

                    if (result == -1)
                        linuwux_debug_observation(
                            "arch-set-cpuid-enable-failed",
                            (uint64_t)call_errno,
                            (uint64_t)result);

                    __asm__ volatile(
                        "cpuid"
                        : "=a"(ucontext->uc_mcontext.gregs[REG_RAX]),
                                     "=b"(ucontext->uc_mcontext.gregs[REG_RBX]),
                                     "=c"(ucontext->uc_mcontext.gregs[REG_RCX]),
                                     "=d"(ucontext->uc_mcontext.gregs[REG_RDX])
                                     : "a"(leaf), "c"(subleaf)
                                     : "memory"
                    );

                    result = syscall(SYS_arch_prctl, ARCH_SET_CPUID, 0);
                    call_errno = errno;

                    if (result == -1)
                        linuwux_debug_observation(
                            "arch-set-cpuid-rearm-failed",
                            (uint64_t)call_errno,
                            (uint64_t)result);
                }
                break;
        }

        ucontext->uc_mcontext.gregs[REG_RIP] += 2;
        return 1;
    }

    return 0;
}

static int linuwux_redirect_syscall(ucontext_t *ctx, uint64_t target)
{
    __uint128_t *xmm_regs = (__uint128_t *)ctx->uc_mcontext.fpregs->_xmm;

    xmm_regs[4] = ctx->uc_mcontext.gregs[REG_RAX] & 0xFFFFFFFF;
    ctx->uc_mcontext.gregs[REG_RAX] = ctx->uc_mcontext.gregs[REG_RCX];
    ctx->uc_mcontext.gregs[REG_RCX] = target;
    ctx->uc_mcontext.gregs[REG_RIP] = target;

    return 1;
}

static int linuwux_handle_sigsys(void *sigcontext)
{
    ucontext_t *ctx = sigcontext;
    __uint128_t *xmm_regs = (__uint128_t *)ctx->uc_mcontext.fpregs->_xmm;
    uint32_t syscall_id = (uint32_t)ctx->uc_mcontext.gregs[REG_RAX];

    if ((xmm_regs[5] & 0xFFFFFFFFFFFFFFFF) == SyscallBypassMagic)
    {
        xmm_regs[5] = 0;
        /* MESSAGE("SyscallBypassMagic!\n"); */
        return 0;
    }

    if (ctx->uc_mcontext.gregs[REG_RAX] == 0xffff)
        return 0;

    if (ctx->uc_mcontext.gregs[REG_RAX] == 0x7fffffffffff)
        return 0;

    /*
     * First routable SIGSYS resolves an ambiguous registration as CURRENT.
     * Pure state mutation only: no mmap/mprotect/sysconf/logging here.
     */
    linuwux_commit_pending_current_route();

    if (linuwux_router.qsi.target_valid &&
        linuwux_router.qsi.syscall_id_valid &&
        linuwux_router.qsi.target != 0 &&
        syscall_id == linuwux_router.qsi.syscall_id &&
        ctx->uc_mcontext.gregs[REG_R10] <= 0)
        return linuwux_redirect_syscall(ctx, linuwux_router.qsi.target);

    if (linuwux_router.qfa.target_valid &&
        linuwux_router.qfa.syscall_id_valid &&
        linuwux_router.qfa.target != 0 &&
        syscall_id == linuwux_router.qfa.syscall_id)
        return linuwux_redirect_syscall(ctx, linuwux_router.qfa.target);

    if (linuwux_router.generic_target != 0)
        return linuwux_redirect_syscall(ctx, linuwux_router.generic_target);

    return 0;
}

#endif /* LINUWUX_HOOKS_INCLUDED */
