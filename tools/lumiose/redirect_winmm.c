/*
 * Lumiose Private Server Network Redirector & System32 winmm.dll Proxy.
 *
 * Self-contained Win64 C implementation (no Windows SDK headers required)
 * designed to compile cleanly with the bundled Zig toolchain in Lumiose Online.
 *
 * When LUMIOSE_SERVER_OVERRIDE=host:port is set in the environment and differs
 * from the official endpoint (135.148.167.226:27777), this DLL patches
 * lasrecomp.exe's WS2_32.dll IAT entries for sendto/recvfrom so UDP packets
 * addressed to the official endpoint are routed to host:port (supporting both
 * IPv4 literals and DNS hostnames), while responses are mapped back to the
 * official address expected by subsdk9 and lumiose_network.c.
 */

#include <stdint.h>
#include <stddef.h>

#define OFFICIAL_IP_DEFAULT "135.148.167.226"
#define OFFICIAL_PORT_DEFAULT 27777u
#define MAX_WINMM_FWD 512

#define DLL_PROCESS_DETACH 0
#define DLL_PROCESS_ATTACH 1

#define AF_INET 2
#define SOCK_DGRAM 2
#define IPPROTO_UDP 17
#define SOCKET_ERROR (-1)
#define WSAHOST_UNREACH 10065
#define PAGE_READWRITE 0x04u

#define IMAGE_DOS_SIGNATURE 0x5A4Du
#define IMAGE_NT_SIGNATURE 0x00004550u
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define IMAGE_ORDINAL_FLAG64 0x8000000000000000ULL

typedef int BOOL;
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif
typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef unsigned int UINT;
typedef uint64_t ULONGLONG;
typedef uintptr_t SOCKET;
typedef void *HMODULE;
typedef HMODULE HINSTANCE;
typedef void *LPVOID;
typedef void *PVOID;
typedef const char *LPCSTR;
typedef const uint16_t *LPCWSTR;
typedef uint16_t *LPWSTR;

#define WINAPI __stdcall
#define WSAAPI __stdcall
#define CALLBACK __stdcall

typedef union {
    PVOID Ptr;
} RTL_RUN_ONCE, *PRTL_RUN_ONCE;
typedef RTL_RUN_ONCE INIT_ONCE;
typedef PRTL_RUN_ONCE PINIT_ONCE;
#define INIT_ONCE_STATIC_INIT { 0 }

typedef BOOL (CALLBACK *PINIT_ONCE_FN)(PINIT_ONCE, PVOID, PVOID *);

typedef struct {
    void *DebugInfo;
    int32_t LockCount;
    int32_t RecursionCount;
    void *OwningThread;
    void *LockSemaphore;
    uintptr_t SpinCount;
} CRITICAL_SECTION;

struct in_addr {
    uint32_t s_addr;
};

struct sockaddr {
    uint16_t sa_family;
    char sa_data[14];
};

struct sockaddr_in {
    uint16_t sin_family;
    uint16_t sin_port;
    struct in_addr sin_addr;
    char sin_zero[8];
};

struct addrinfo {
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    size_t ai_addrlen;
    char *ai_canonname;
    struct sockaddr *ai_addr;
    struct addrinfo *ai_next;
};

#pragma pack(push, 1)
typedef struct {
    WORD e_magic;
    WORD e_cblp;
    WORD e_cp;
    WORD e_crlc;
    WORD e_cparhdr;
    WORD e_minalloc;
    WORD e_maxalloc;
    WORD e_ss;
    WORD e_sp;
    WORD e_csum;
    WORD e_ip;
    WORD e_cs;
    WORD e_lfarlc;
    WORD e_ovno;
    WORD e_res[4];
    WORD e_oemid;
    WORD e_oeminfo;
    WORD e_res2[10];
    int32_t e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct {
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY;

typedef struct {
    WORD Machine;
    WORD NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader;
    WORD Characteristics;
} IMAGE_FILE_HEADER;

typedef struct {
    WORD Magic;
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    ULONGLONG ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD Subsystem;
    WORD DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64;

typedef struct {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64;

typedef struct {
    DWORD OriginalFirstThunk;
    DWORD TimeDateStamp;
    DWORD ForwarderChain;
    DWORD Name;
    DWORD FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;

typedef struct {
    union {
        ULONGLONG ForwarderString;
        ULONGLONG Function;
        ULONGLONG Ordinal;
        ULONGLONG AddressOfData;
    } u1;
} IMAGE_THUNK_DATA64;

typedef struct {
    WORD Hint;
    char Name[1];
} IMAGE_IMPORT_BY_NAME;
#pragma pack(pop)

/* kernel32.lib imports */
__declspec(dllimport) BOOL WINAPI DisableThreadLibraryCalls(HMODULE hLibModule);
__declspec(dllimport) UINT WINAPI GetSystemDirectoryW(LPWSTR lpBuffer, UINT uSize);
__declspec(dllimport) HMODULE WINAPI LoadLibraryW(LPCWSTR lpLibFileName);
__declspec(dllimport) HMODULE WINAPI LoadLibraryA(LPCSTR lpLibFileName);
__declspec(dllimport) BOOL WINAPI FreeLibrary(HMODULE hLibModule);
__declspec(dllimport) HMODULE WINAPI GetModuleHandleW(LPCWSTR lpModuleName);
__declspec(dllimport) HMODULE WINAPI GetModuleHandleA(LPCSTR lpModuleName);
__declspec(dllimport) void *WINAPI GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
__declspec(dllimport) DWORD WINAPI GetEnvironmentVariableA(LPCSTR lpName, char *lpBuffer, DWORD nSize);
__declspec(dllimport) BOOL WINAPI InitOnceExecuteOnce(PINIT_ONCE InitOnce, PINIT_ONCE_FN InitFn, PVOID Parameter, PVOID *Context);
__declspec(dllimport) void WINAPI InitializeCriticalSection(CRITICAL_SECTION *lpCriticalSection);
__declspec(dllimport) void WINAPI EnterCriticalSection(CRITICAL_SECTION *lpCriticalSection);
__declspec(dllimport) void WINAPI LeaveCriticalSection(CRITICAL_SECTION *lpCriticalSection);
__declspec(dllimport) void WINAPI DeleteCriticalSection(CRITICAL_SECTION *lpCriticalSection);
__declspec(dllimport) BOOL WINAPI VirtualProtect(LPVOID lpAddress, size_t dwSize, DWORD flNewProtect, DWORD *lpflOldProtect);
__declspec(dllimport) ULONGLONG WINAPI GetTickCount64(void);
__declspec(dllimport) void WINAPI OutputDebugStringA(LPCSTR lpOutputString);

typedef struct {
    const char *name;
    uint16_t ordinal;
} WinmmExportEntry;

#include "redirect_winmm_table.inc"

void *g_winmm_fwd[MAX_WINMM_FWD];

static HMODULE g_real_winmm = NULL;
static INIT_ONCE g_winmm_once = INIT_ONCE_STATIC_INIT;

typedef int (WSAAPI *fn_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
typedef void (WSAAPI *fn_freeaddrinfo)(struct addrinfo *);
typedef void (WSAAPI *fn_WSASetLastError)(int);

static fn_getaddrinfo p_getaddrinfo = NULL;
static fn_freeaddrinfo p_freeaddrinfo = NULL;
static fn_WSASetLastError p_WSASetLastError = NULL;

static int (WSAAPI *orig_sendto)(SOCKET s, const char *buf, int len, int flags,
                                 const struct sockaddr *to, int tolen) = NULL;
static int (WSAAPI *orig_recvfrom)(SOCKET s, char *buf, int len, int flags,
                                   struct sockaddr *from, int *fromlen) = NULL;

static CRITICAL_SECTION g_net_lock;
static int g_hook_active = 0;
static struct in_addr g_match_addr;
static uint16_t g_match_port_be = 0;

static char g_override_host[256];
static char g_override_port_str[16];
static struct sockaddr_in g_override_addr;
static int g_override_resolved = 0;
static ULONGLONG g_last_resolve_ms = 0;
static BYTE g_knock_pkt[72];
static int g_knock_len = 0;

void *memcpy(void *dst, const void *src, size_t n) {
    volatile BYTE *d = (volatile BYTE *)dst;
    const volatile BYTE *s = (const volatile BYTE *)src;
    for (size_t i = 0; i < n; ++i) d[i] = s[i];
    return dst;
}

void *memset(void *dst, int val, size_t n) {
    volatile BYTE *d = (volatile BYTE *)dst;
    for (size_t i = 0; i < n; ++i) d[i] = (BYTE)val;
    return dst;
}

size_t strlen(const char *s) {
    size_t n = 0;
    while (s && s[n]) n++;
    return n;
}

static size_t c_strlen(const char *s) {
    return strlen(s);
}

static void c_memcpy(void *dst, const void *src, size_t n) {
    memcpy(dst, src, n);
}

static void c_memset(void *dst, int val, size_t n) {
    memset(dst, val, n);
}

static int c_strcmp(const char *a, const char *b) {
    while (*a && (*a == *b)) {
        a++;
        b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

static int eq_ascii_nocase(const char *a, const char *b) {
    if (!a || !b) return 0;
    while (*a && *b) {
        char ca = (*a >= 'A' && *a <= 'Z') ? (char)(*a + 32) : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? (char)(*b + 32) : *b;
        if (ca != cb) return 0;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

static uint16_t u16_htons(uint16_t v) {
    return (uint16_t)(((v & 0x00FFu) << 8) | ((v & 0xFF00u) >> 8));
}

static int parse_u16(const char *s, uint16_t *out) {
    if (!s || *s < '0' || *s > '9') return 0;
    uint32_t val = 0;
    while (*s >= '0' && *s <= '9') {
        val = val * 10u + (uint32_t)(*s - '0');
        if (val > 65535u) return 0;
        s++;
    }
    while (*s == ' ' || *s == '\t') s++;
    if (*s != '\0' || val == 0u) return 0;
    *out = (uint16_t)val;
    return 1;
}

static int parse_ipv4_literal(const char *s, struct in_addr *out) {
    if (!s || !*s || !out) return 0;
    uint8_t parts[4] = {0, 0, 0, 0};
    const char *p = s;
    for (int i = 0; i < 4; ++i) {
        if (*p < '0' || *p > '9') return 0;
        uint32_t val = 0;
        int digits = 0;
        while (*p >= '0' && *p <= '9') {
            val = val * 10u + (uint32_t)(*p - '0');
            if (val > 255u) return 0;
            p++;
            digits++;
        }
        if (digits == 0) return 0;
        parts[i] = (uint8_t)val;
        if (i < 3) {
            if (*p != '.') return 0;
            p++;
        }
    }
    if (*p != '\0') return 0;
    uint8_t *b = (uint8_t *)&out->s_addr;
    b[0] = parts[0];
    b[1] = parts[1];
    b[2] = parts[2];
    b[3] = parts[3];
    return 1;
}

static void u16_to_str(uint16_t val, char *out) {
    char tmp[8];
    int n = 0;
    do {
        tmp[n++] = (char)('0' + (val % 10u));
        val /= 10u;
    } while (val > 0u);
    for (int i = 0; i < n; ++i) {
        out[i] = tmp[n - 1 - i];
    }
    out[n] = '\0';
}

static void ensure_ws2_helpers(void) {
    if (p_getaddrinfo && p_freeaddrinfo) return;
    HMODULE ws2 = GetModuleHandleA("ws2_32.dll");
    if (!ws2) ws2 = LoadLibraryA("ws2_32.dll");
    if (!ws2) return;
    if (!p_getaddrinfo) p_getaddrinfo = (fn_getaddrinfo)GetProcAddress(ws2, "getaddrinfo");
    if (!p_freeaddrinfo) p_freeaddrinfo = (fn_freeaddrinfo)GetProcAddress(ws2, "freeaddrinfo");
    if (!p_WSASetLastError) p_WSASetLastError = (fn_WSASetLastError)GetProcAddress(ws2, "WSASetLastError");
}

static BOOL CALLBACK init_real_winmm(PINIT_ONCE once, PVOID param, PVOID *ctx) {
    (void)once;
    (void)param;
    (void)ctx;

    uint16_t dll_path[300];
    UINT n = GetSystemDirectoryW(dll_path, 260);
    static const char suffix[] = "\\winmm.dll";
    if (n > 0 && n < 260) {
        for (size_t i = 0; i <= sizeof(suffix) - 1; ++i) {
            dll_path[n + i] = (uint16_t)(unsigned char)suffix[i];
        }
    } else {
        static const char fallback[] = "C:\\Windows\\System32\\winmm.dll";
        for (size_t i = 0; i <= sizeof(fallback) - 1; ++i) {
            dll_path[i] = (uint16_t)(unsigned char)fallback[i];
        }
    }

    g_real_winmm = LoadLibraryW(dll_path);
    if (!g_real_winmm) {
        return FALSE;
    }

    for (size_t i = 0; i < g_winmm_export_count && i < MAX_WINMM_FWD; ++i) {
        if (g_winmm_exports[i].name != NULL) {
            g_winmm_fwd[i] = GetProcAddress(g_real_winmm, g_winmm_exports[i].name);
        } else {
            g_winmm_fwd[i] = GetProcAddress(
                g_real_winmm, (LPCSTR)(uintptr_t)g_winmm_exports[i].ordinal);
        }
    }
    return TRUE;
}

static void ensure_winmm(void) {
    InitOnceExecuteOnce(&g_winmm_once, init_real_winmm, NULL, NULL);
}

static int parse_host_port(const char *spec, char *host_out, size_t host_cap,
                           char *port_out, size_t port_cap, uint16_t *port_num_out) {
    if (!spec || !*spec || port_cap < 8) return 0;
    while (*spec == ' ' || *spec == '\t') spec++;

    const char *colon = NULL;
    for (const char *p = spec; *p; ++p) {
        if (*p == ':') colon = p;
    }
    if (!colon || colon == spec || !*(colon + 1)) return 0;

    size_t hlen = (size_t)(colon - spec);
    if (hlen >= host_cap) return 0;
    c_memcpy(host_out, spec, hlen);
    host_out[hlen] = '\0';
    while (hlen > 0 && (host_out[hlen - 1] == ' ' || host_out[hlen - 1] == '\t')) {
        host_out[--hlen] = '\0';
    }
    if (hlen == 0) return 0;

    uint16_t port_val = 0;
    if (!parse_u16(colon + 1, &port_val)) return 0;
    u16_to_str(port_val, port_out);
    if (port_num_out) *port_num_out = port_val;
    return 1;
}

static int resolve_override_locked(int force) {
    ULONGLONG now = GetTickCount64();
    if (g_override_resolved && !force && (now - g_last_resolve_ms) < 30000ULL) {
        return 1;
    }

    ensure_ws2_helpers();
    if (!p_getaddrinfo || !p_freeaddrinfo) {
        return g_override_resolved;
    }

    struct addrinfo hints;
    struct addrinfo *res = NULL;
    c_memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    int rc = p_getaddrinfo(g_override_host, g_override_port_str, &hints, &res);
    if (rc == 0 && res != NULL && res->ai_addrlen >= sizeof(struct sockaddr_in)) {
        c_memcpy(&g_override_addr, res->ai_addr, sizeof(struct sockaddr_in));
        p_freeaddrinfo(res);
        g_override_resolved = 1;
        g_last_resolve_ms = now;
        return 1;
    }
    if (res != NULL) p_freeaddrinfo(res);
    return g_override_resolved;
}

static int WSAAPI hook_sendto(SOCKET s, const char *buf, int len, int flags,
                              const struct sockaddr *to, int tolen) {
    if (!orig_sendto) return SOCKET_ERROR;

    if (to && tolen >= (int)sizeof(struct sockaddr_in) && to->sa_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)to;
        if (in->sin_addr.s_addr == g_match_addr.s_addr && in->sin_port == g_match_port_be) {
            struct sockaddr_in dst;
            int resolved = 0;

            EnterCriticalSection(&g_net_lock);
            resolved = resolve_override_locked(0);
            if (resolved) {
                dst = g_override_addr;
            }
            LeaveCriticalSection(&g_net_lock);

            if (!resolved) {
                ensure_ws2_helpers();
                if (p_WSASetLastError) p_WSASetLastError(WSAHOST_UNREACH);
                return SOCKET_ERROR;
            }
            if (g_knock_len > 0 && buf && len >= 130 &&
                (BYTE)buf[0] == 'Z' && (BYTE)buf[1] == 'A' &&
                (BYTE)buf[2] == 1 && (BYTE)buf[3] == 1) {
                orig_sendto(s, (const char *)g_knock_pkt, g_knock_len, 0,
                            (const struct sockaddr *)&dst, sizeof(dst));
            }
            return orig_sendto(s, buf, len, flags, (const struct sockaddr *)&dst, sizeof(dst));
        }
    }
    return orig_sendto(s, buf, len, flags, to, tolen);
}

static int WSAAPI hook_recvfrom(SOCKET s, char *buf, int len, int flags,
                                struct sockaddr *from, int *fromlen) {
    if (!orig_recvfrom) return SOCKET_ERROR;

    int rc = orig_recvfrom(s, buf, len, flags, from, fromlen);
    if (rc >= 0 && from && fromlen && *fromlen >= (int)sizeof(struct sockaddr_in) &&
        from->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)from;
        int match = 0;
        EnterCriticalSection(&g_net_lock);
        if (g_override_resolved &&
            in->sin_addr.s_addr == g_override_addr.sin_addr.s_addr &&
            in->sin_port == g_override_addr.sin_port) {
            match = 1;
        }
        LeaveCriticalSection(&g_net_lock);

        if (match) {
            in->sin_addr = g_match_addr;
            in->sin_port = g_match_port_be;
        }
    }
    return rc;
}

static int patch_iat_ws2(HMODULE mod) {
    if (!mod) return 0;
    BYTE *base = (BYTE *)mod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    IMAGE_DATA_DIRECTORY *dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir->VirtualAddress || !dir->Size) return 0;

    HMODULE ws2 = GetModuleHandleA("ws2_32.dll");
    if (!ws2) ws2 = LoadLibraryA("ws2_32.dll");
    void *real_sendto = ws2 ? GetProcAddress(ws2, "sendto") : NULL;
    void *real_recvfrom = ws2 ? GetProcAddress(ws2, "recvfrom") : NULL;

    int patched = 0;
    IMAGE_IMPORT_DESCRIPTOR *desc = (IMAGE_IMPORT_DESCRIPTOR *)(base + dir->VirtualAddress);
    for (; desc->Name; ++desc) {
        const char *dll_name = (const char *)(base + desc->Name);
        if (!eq_ascii_nocase(dll_name, "ws2_32.dll")) continue;

        IMAGE_THUNK_DATA64 *ilt = desc->OriginalFirstThunk
            ? (IMAGE_THUNK_DATA64 *)(base + desc->OriginalFirstThunk)
            : NULL;
        IMAGE_THUNK_DATA64 *iat = (IMAGE_THUNK_DATA64 *)(base + desc->FirstThunk);

        for (size_t idx = 0; iat[idx].u1.Function; ++idx) {
            const char *fn_name = NULL;
            if (ilt && ilt[idx].u1.AddressOfData &&
                !(ilt[idx].u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
                IMAGE_IMPORT_BY_NAME *ibn =
                    (IMAGE_IMPORT_BY_NAME *)(base + (DWORD)ilt[idx].u1.AddressOfData);
                fn_name = (const char *)ibn->Name;
            }

            void **slot = (void **)&iat[idx].u1.Function;
            void *cur = *slot;

            if ((fn_name && c_strcmp(fn_name, "sendto") == 0) ||
                (real_sendto && cur == real_sendto)) {
                DWORD old_prot = 0;
                if (VirtualProtect(slot, sizeof(*slot), PAGE_READWRITE, &old_prot)) {
                    if (!orig_sendto) {
                        orig_sendto = (int (WSAAPI *)(SOCKET, const char *, int, int,
                                                      const struct sockaddr *, int))cur;
                    }
                    *slot = (void *)hook_sendto;
                    VirtualProtect(slot, sizeof(*slot), old_prot, &old_prot);
                    patched |= 1;
                }
            } else if ((fn_name && c_strcmp(fn_name, "recvfrom") == 0) ||
                       (real_recvfrom && cur == real_recvfrom)) {
                DWORD old_prot = 0;
                if (VirtualProtect(slot, sizeof(*slot), PAGE_READWRITE, &old_prot)) {
                    if (!orig_recvfrom) {
                        orig_recvfrom = (int (WSAAPI *)(SOCKET, char *, int, int,
                                                        struct sockaddr *, int *))cur;
                    }
                    *slot = (void *)hook_recvfrom;
                    VirtualProtect(slot, sizeof(*slot), old_prot, &old_prot);
                    patched |= 2;
                }
            }
        }
    }
    return patched;
}

static void append_str(char *dst, size_t cap, size_t *pos, const char *src) {
    size_t n = c_strlen(src);
    for (size_t i = 0; i < n && (*pos + 1) < cap; ++i) {
        dst[(*pos)++] = src[i];
    }
    dst[*pos] = '\0';
}

static void init_redirector(void) {
    char spec[300];
    DWORD len = GetEnvironmentVariableA("LUMIOSE_SERVER_OVERRIDE", spec, sizeof(spec));
    if (len == 0 || len >= sizeof(spec)) return;

    char host[256];
    char port_str[16];
    uint16_t ov_port = 0;
    if (!parse_host_port(spec, host, sizeof(host), port_str, sizeof(port_str), &ov_port)) return;

    char match_host[256] = OFFICIAL_IP_DEFAULT;
    char match_port_str[16] = "27777";
    uint16_t match_port = (uint16_t)OFFICIAL_PORT_DEFAULT;
    char test_spec[300];
    DWORD tlen = GetEnvironmentVariableA("LUMIOSE_TEST_SERVER", test_spec, sizeof(test_spec));
    if (tlen > 0 && tlen < sizeof(test_spec)) {
        parse_host_port(test_spec, match_host, sizeof(match_host),
                        match_port_str, sizeof(match_port_str), &match_port);
    }

    if (c_strcmp(host, match_host) == 0 && c_strcmp(port_str, match_port_str) == 0) {
        return;
    }

    if (!parse_ipv4_literal(match_host, &g_match_addr)) {
        parse_ipv4_literal(OFFICIAL_IP_DEFAULT, &g_match_addr);
    }
    g_match_port_be = u16_htons(match_port);

    c_memcpy(g_override_host, host, c_strlen(host) + 1);
    c_memcpy(g_override_port_str, port_str, c_strlen(port_str) + 1);

    char secret[65];
    DWORD slen = GetEnvironmentVariableA("LUMIOSE_ROOM_SECRET", secret, sizeof(secret));
    if (slen > 0 && slen <= 64) {
        static const char magic[8] = {'Z','A','K','N','O','C','K','!'};
        c_memcpy(g_knock_pkt, magic, 8);
        c_memcpy(g_knock_pkt + 8, secret, slen);
        g_knock_len = 8 + (int)slen;
    } else {
        g_knock_len = 0;
    }

    struct in_addr ov_in;
    if (parse_ipv4_literal(g_override_host, &ov_in)) {
        c_memset(&g_override_addr, 0, sizeof(g_override_addr));
        g_override_addr.sin_family = AF_INET;
        g_override_addr.sin_addr = ov_in;
        g_override_addr.sin_port = u16_htons(ov_port);
        g_override_resolved = 1;
        g_last_resolve_ms = GetTickCount64();
    }

    InitializeCriticalSection(&g_net_lock);
    if (patch_iat_ws2(GetModuleHandleW(NULL))) {
        g_hook_active = 1;
        char dbg[400];
        size_t pos = 0;
        dbg[0] = '\0';
        append_str(dbg, sizeof(dbg), &pos, "[lumiose redirect] routing ");
        append_str(dbg, sizeof(dbg), &pos, match_host);
        append_str(dbg, sizeof(dbg), &pos, ":");
        append_str(dbg, sizeof(dbg), &pos, match_port_str);
        append_str(dbg, sizeof(dbg), &pos, " -> ");
        append_str(dbg, sizeof(dbg), &pos, g_override_host);
        append_str(dbg, sizeof(dbg), &pos, ":");
        append_str(dbg, sizeof(dbg), &pos, g_override_port_str);
        append_str(dbg, sizeof(dbg), &pos, "\n");
        OutputDebugStringA(dbg);
    }
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);
        ensure_winmm();
        init_redirector();
    } else if (reason == DLL_PROCESS_DETACH) {
        if (g_hook_active) {
            DeleteCriticalSection(&g_net_lock);
            g_hook_active = 0;
        }
        if (g_real_winmm) {
            FreeLibrary(g_real_winmm);
            g_real_winmm = NULL;
        }
    }
    return TRUE;
}
