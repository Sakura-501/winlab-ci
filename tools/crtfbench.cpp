// crtfbench.cpp - in-process driver for OLMAPI32's MS-OXRTFCP 'LZFu' decompressor
// Usage: crtfbench <blob|-> [flags-hex] [readchunk] [mode]
//   mode 0 = Wrap + read to EOF            (default)
//   mode 1 = Wrap + seek pattern + read
//   mode 2 = Wrap + Stat + Clone + read
// Prints: WRAP rc= / READS n got= / SEEK rc= / and on AV: AV code rw= target= module+rva
#include <windows.h>
#include <intrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <objbase.h>
#include <tlhelp32.h>

typedef HRESULT (STDAPICALLTYPE *PFN_WRAP)(IStream *, ULONG, IStream **);
typedef HRESULT (STDAPICALLTYPE *PFN_OPEN_TNEF)(IStream *, void **, LPCSTR, ULONG, void *, void *, void *);
typedef HRESULT (STDAPICALLTYPE *PFN_OPEN_TNEF8)(void *, void *, char *, unsigned long, void *, unsigned short, void *, void **);
typedef HRESULT (STDAPICALLTYPE *PFN_TNEF_CALL)(void *, unsigned long, void *, void **);
typedef HRESULT (STDAPICALLTYPE *PFN_OPEN_TAGGED_BODY)(void *, void *, unsigned long, IStream **);
typedef HRESULT (STDAPICALLTYPE *PFN_QI)(void *, const GUID *, void **);
typedef HRESULT (STDAPICALLTYPE *PFN_GET_TNEF_STM)(void *, IStream **);
typedef HRESULT (STDAPICALLTYPE *PFN_RTFSYNC)(void *, ULONG, int *);
typedef HRESULT (STDAPICALLTYPE *PFN_PARSE_ADDR)(ULONG, ULONG, const char *, void *);
typedef HRESULT (STDAPICALLTYPE *PFN_OPEN_TNEF_MSG)(void *, IStream *, void **, LPCSTR, ULONG, void *, void *);
typedef HRESULT (STDAPICALLTYPE *PFN_OPENMSGSESS)(void *, ULONG, void **);
typedef HRESULT (STDAPICALLTYPE *PFN_OPENMSGONI)(void *, void *, void *, void *, void *, void *, void *, void *, ULONG, ULONG, void **);
typedef HRESULT (STDAPICALLTYPE *PFN_ALLOCBUF)(ULONG, void **);
typedef HRESULT (STDAPICALLTYPE *PFN_ALLOCMORE)(ULONG, void *, void **);
typedef void (STDAPICALLTYPE *PFN_FREEBUF)(void *);
typedef HRESULT (STDAPICALLTYPE *PFN_MAPIINIT)(void *);
typedef HRESULT (STDAPICALLTYPE *PFN_MAPIUNINIT)(void);
typedef int (STDAPICALLTYPE *PFN_DASEX)(unsigned long, const char *, unsigned char *, unsigned long, unsigned long, void *, void *, unsigned long *);
typedef ULONG (STDAPICALLTYPE *PFN_RELEASE)(void *);
typedef HRESULT (STDAPICALLTYPE *PFN_OPENPROP)(void *, unsigned long, const void *, unsigned long, unsigned long, void **);

static PFN_WRAP       g_pWrap = nullptr;
static PFN_WRAP       g_pWrapEx = nullptr;
static HMODULE        g_hOlm = nullptr;
static char           g_modname[260] = {0};
static uintptr_t      g_modbase = 0;
static volatile LONG  g_in_handler = 0;

// ---- mode 48: OLMAPI32's own view of free(), observed through its IAT slot ----
// The UCRT allocator accepts a second free of the same chunk without faulting, so "no crash" is
// not evidence that only one release ran. Rewriting only the target module's slot attributes every
// logged release to a specific instruction inside that module, and counts releases per pointer.
struct DFREC { void *p; void *r1; void *r2; int n; };
static DFREC g_df[8192];
static int g_dfen = 0, g_dfdbl = 0, g_dfall = 0;
static volatile int g_dfinhook = 0;
static unsigned char *g_dfmod = nullptr;
typedef void (STDAPICALLTYPE *PFN_FREE_T)(void *);
static PFN_FREE_T g_dfreal = nullptr;
// The alloc side of the same observation: the sizes OLMAPI32 asks for say whether a routine ever
// ran, which the release counts alone cannot show (a call that returns before the descriptor
// converter produces the same handful of releases as one that fails inside it).
static void *g_am[4096];
static size_t g_asz[4096];
static unsigned char *g_art[4096];
static int g_amn = 0;
typedef void *(STDAPICALLTYPE *PFN_MALLOC_T)(size_t);
static PFN_MALLOC_T g_dmreal = nullptr;
static void * STDAPICALLTYPE HookMalloc(size_t n) {
    void *ra = _ReturnAddress();
    void *p = g_dmreal ? g_dmreal(n) : nullptr;
    if (g_dfinhook == 0) {
        g_dfinhook = 1;
        // printed as it happens: the call can end up in the transport and never come back, and a
        // buffer held until then would lose exactly the allocations being looked for
        printf("A %llu %p -%08llX\n", (unsigned long long)n, p,
               g_dfmod ? (unsigned long long)((unsigned char *)ra - (unsigned char *)g_dfmod) : 0ull);
        fflush(stdout);
        g_dfinhook = 0;
    }
    if (g_amn < 4096) { g_am[g_amn] = p; g_asz[g_amn] = n; g_art[g_amn] = (unsigned char *)ra; g_amn++; }
    return p;
}

static void STDAPICALLTYPE HookFree(void *p) {
    void *ra = _ReturnAddress();
    if (g_dfinhook) { if (g_dfreal) g_dfreal(p); return; }
    g_dfinhook = 1;
    printf("F %p -%08llX n=%d\n", p,
           g_dfmod ? (unsigned long long)((unsigned char *)ra - (unsigned char *)g_dfmod) : 0ull,
           0); fflush(stdout);
    int i;
    for (i = 0; i < g_dfen; i++) if (g_df[i].p == p) break;
    if (i < g_dfen) {
        g_df[i].n++;
        if (g_df[i].n >= 2) {
            g_df[i].r2 = ra; g_dfdbl++;
            printf("DOUBLEFREE p=%p first=olmapi32+0t%llX second=olmapi32+0t%llX\n", p,
                   (unsigned long long)((char *)g_df[i].r1 - (char *)g_dfmod),
                   (unsigned long long)((char *)ra - (char *)g_dfmod)); fflush(stdout);
        }
    } else if (g_dfen < 8192) {
        g_df[g_dfen].p = p; g_df[g_dfen].r1 = ra; g_df[g_dfen].n = 1; g_dfen++;
    }
    g_dfall++;
    g_dfinhook = 0;
    if (g_dfreal) g_dfreal(p);
}

static volatile LONG  g_soft = 0;        // mode 40: report the fault and let SEH swallow it
static unsigned long  g_faults = 0;

static void ModuleFor(uintptr_t a, char *out, size_t cch, uintptr_t *base)
{
    MEMORY_BASIC_INFORMATION mbi;
    out[0] = 0; *base = 0;
    if (VirtualQuery((PVOID)a, &mbi, sizeof(mbi)) == 0) return;
    if (mbi.AllocationBase == nullptr) return;
    GetModuleFileNameA((HMODULE)mbi.AllocationBase, out, (DWORD)cch);
    *base = (uintptr_t)mbi.AllocationBase;
}

static const char *Base(const char *p)
{
    const char *s = strrchr(p, '\\');
    return s ? s + 1 : p;
}

static LONG CALLBACK VehReport(PEXCEPTION_POINTERS ep)
{
    // __fastfail (int 0x29) is deliberately uncatchable by SEH, but a vectored handler still sees
    // it before termination - without this the wave just dies with rc=0xC0000409 and no location.
    DWORD c = ep->ExceptionRecord->ExceptionCode;
    if (c == 0xC0000409 || c == 0xC0000374 || c == 0xC0000379 || c == 0xC0000389 || c == 0x80000003) {
        char mod[260]; uintptr_t base = 0;
        ModuleFor((uintptr_t)ep->ExceptionRecord->ExceptionAddress, mod, sizeof(mod), &base);
        printf("!!!VEH code=%08x addr=%p %s+0x%llX sub=%u\n", (unsigned)c,
               (void *)ep->ExceptionRecord->ExceptionAddress, Base(mod),
               base ? (unsigned long long)((uintptr_t)ep->ExceptionRecord->ExceptionAddress - base) : 0ULL,
               (c == 0xC0000409 && ep->ExceptionRecord->NumberParameters > 1)
                   ? (unsigned)ep->ExceptionRecord->ExceptionInformation[1] : 0u);
        fflush(stdout);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}


static BOOL TargetReadable(uintptr_t a)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (a == 0) return FALSE;
    if (VirtualQuery((PVOID)a, &mbi, sizeof(mbi)) == 0) return FALSE;
    if (mbi.State != MEM_COMMIT) return FALSE;
    DWORD ok = PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
               PAGE_WRITECOPY | PAGE_WRITECOPY | PAGE_TARGETS_INVALID;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return FALSE;
    return (mbi.Protect & ok) != 0;
}

LONG CALLBACK Veh(PEXCEPTION_POINTERS ep)
{
    if (InterlockedCompareExchange(&g_in_handler, 1, 0) != 0)
        return EXCEPTION_CONTINUE_SEARCH;
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (code == EXCEPTION_ACCESS_VIOLATION || code == 0xC0000409 || code == 0xC0000374 ||
        code == 0x80000003 || code == (DWORD)0xC00000FD) {
        if (code != EXCEPTION_ACCESS_VIOLATION) {
            printf("!!!EXC code=%08x addr=%p\n", (unsigned)code, ep->ExceptionRecord->ExceptionAddress);
            fflush(stdout);
            InterlockedExchange(&g_in_handler, 0);
            if (g_soft) { InterlockedIncrement(&g_faults); return EXCEPTION_CONTINUE_SEARCH; }
            TerminateProcess(GetCurrentProcess(), code);
        }
        ULONG_PTR info0 = ep->ExceptionRecord->ExceptionInformation[0];
        ULONG_PTR info1 = ep->ExceptionRecord->ExceptionInformation[1];
        uintptr_t addr = (uintptr_t)ep->ExceptionRecord->ExceptionAddress;
        char mod[260]; uintptr_t base = 0;
        ModuleFor(addr, mod, sizeof(mod), &base);
        printf("!!!AV code=%08x rw=%llu target=0x%llX addr=%p %s+0x%llX\n",
               (unsigned)code, (unsigned long long)info0, (unsigned long long)info1,
               (void *)addr, Base(mod), base ? (unsigned long long)(addr - base) : 0ULL);
        fflush(stdout);
        CONTEXT *c = ep->ContextRecord;
        printf("    RAX=%p RBX=%p RCX=%p RDX=%p RSI=%p RDI=%p RBP=%p RSP=%p R8=%p R9=%p R10=%p R11=%p R12=%p R13=%p R14=%p R15=%p\n",
               (void *)c->Rax, (void *)c->Rbx, (void *)c->Rcx, (void *)c->Rdx, (void *)c->Rsi, (void *)c->Rdi,
               (void *)c->Rbp, (void *)c->Rsp, (void *)c->R8, (void *)c->R9, (void *)c->R10, (void *)c->R11,
               (void *)c->R12, (void *)c->R13, (void *)c->R14, (void *)c->R15);
        if (TargetReadable(addr)) {
            unsigned char b[16];
            memcpy(b, (void *)addr, sizeof(b));
            printf("    CODE:");
            for (int i = 0; i < 16; i++) printf(" %02X", b[i]);
            printf("\n");
        }
        if (TargetReadable(info1)) {
            unsigned char b[32];
            memcpy(b, (void *)info1, sizeof(b));
            printf("    TGTBYTES:");
            for (int i = 0; i < 32; i++) printf(" %02X", b[i]);
            printf("\n");
        }
        fflush(stdout);
        InterlockedExchange(&g_in_handler, 0);
        if (g_soft) { InterlockedIncrement(&g_faults); return EXCEPTION_CONTINUE_SEARCH; }
        TerminateProcess(GetCurrentProcess(), 0xC0000005);
    }
    InterlockedExchange(&g_in_handler, 0);
    return EXCEPTION_CONTINUE_SEARCH;
}

static BYTE *LoadBlob(const char *path, size_t *pcb)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return nullptr;
    DWORD sz = GetFileSize(h, nullptr);
    BYTE *p = (BYTE *)malloc(sz ? sz : 1);
    DWORD rd = 0;
    ::ReadFile(h, p, sz, &rd, nullptr);
    CloseHandle(h);
    *pcb = rd;
    return p;
}


static void HookStat(void);
static DWORD WINAPI Watchdog(LPVOID arg)
{
    DWORD ms = (DWORD)(ULONG_PTR)arg;
    Sleep(ms);
    printf("WATCHDOG_FIRE after=%lu ms\n", ms); fflush(stdout);
    HookStat();
    TerminateProcess(GetCurrentProcess(), 0x48414E47);
    return 0;
}


static HMODULE g_hVal = nullptr;
static ULONG g_lo = 0, g_hi = 0;
static unsigned long g_badrel = 0;

// Release through the object's own vtable slot 2, verifying the target is inside the module's .text
// first (a mis-picked slot must never become a "fault reading").
static unsigned long SafeRelease(void *obj, const char *tag, unsigned long step)
{
    if (!obj) { printf("STEP %lu %s null\n", step, tag); fflush(stdout); return 0; }
    void **vt = (void **)*(void ***)obj;
    void *fn = vt[2];
    if (!g_hVal) { printf("STEP %lu %s noval\n", step, tag); fflush(stdout); return 0; }
    if ((uintptr_t)fn < (uintptr_t)g_hVal + g_lo || (uintptr_t)fn > (uintptr_t)g_hVal + g_hi) {
        g_badrel++;
        printf("BADREL %lu %s obj=%p fn=%p\n", step, tag, obj, fn); fflush(stdout);
        return 0;
    }
    ULONG rc = ((PFN_RELEASE)fn)(obj);
    printf("STEP %lu %s released ref=%lu\n", step, tag, rc); fflush(stdout);
    return 1;
}



// ---- module-side allocator view: the live set, and what a release that is not in it means ----
// A pointer that is released while it is not in the live set is either a second release of a block
// that was already given back, or a release of something this allocator never handed out. Both are
// the class a guard page cannot see: the CRT/segment heap accepts them silently, which is why every
// earlier page-heap wave over these corpora could report no fault and still be missing the defect.
struct HSLOT { void *p; unsigned n; };
static HSLOT g_hs[1 << 16];
static unsigned g_hslive = 0, g_hsnfun = 0, g_hsnew = 0;
// A release of a pointer that is not live has two very different causes, and the old single counter
// merged them: (a) the block was handed out by an allocator whose imports are not observed, so the
// tracker never saw it; (b) the block was tracked, released once already, and is being released
// again - which is the defect class. The tombstone table records every address that was live and
// has since been given back, so a later release can be told apart as (b).
struct HTS { void *p; void *first_ra; unsigned nfree; };
static HTS g_ts[1 << 16];
static unsigned g_tsdup = 0, g_tsunt = 0;
struct HSITE { void *ra; unsigned n; };
static HSITE g_dupsite[512], g_untsite[512];
static int g_ndup = 0, g_nunt = 0;
static int g_tduprep = 0;
static void sAdd(HSITE *t, int *n, void *ra) {
    for (int i = 0; i < *n; i++) if (t[i].ra == ra) { t[i].n++; return; }
    if (*n < 512) { t[*n].ra = ra; t[*n].n = 1; (*n)++; } }
// Resolve a return address to "module+RVA" lazily from one process module snapshot.
struct HMOD { unsigned char *base; unsigned long long sz; char name[260]; char path[300]; };
static HMOD g_mod[512];
static int g_nmod = 0, g_modsnap = 0;
static void wcopy(char *dst, int cch, const WCHAR *src) {
    int n = WideCharToMultiByte(CP_ACP, 0, src, -1, dst, cch - 1, nullptr, nullptr);
    if (n <= 0) dst[0] = 0;
    dst[cch - 1] = 0;
}
static void modSnap(void) {
    HANDLE sn = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (sn == INVALID_HANDLE_VALUE) { printf("MODSNAP_ERR gle=%lu\n", GetLastError()); return; }
    MODULEENTRY32 me; me.dwSize = sizeof(me);
    if (Module32First(sn, &me)) {
        do {
            if (!me.modBaseAddr) continue;
            int seen = 0;
            for (int q = 0; q < g_nmod; q++) if (g_mod[q].base == me.modBaseAddr) { seen = 1; break; }
            if (seen) continue;
            if (g_nmod < 512) {
                g_mod[g_nmod].base = me.modBaseAddr;
                g_mod[g_nmod].sz = me.modBaseSize;
                wcopy(g_mod[g_nmod].name, 260, me.szModule);
                wcopy(g_mod[g_nmod].path, 300, me.szExePath);
                g_nmod++;
            }
        } while (Module32Next(sn, &me));
    }
    CloseHandle(sn);
    g_modsnap = 1;
}
static void raTxt(void *ra, char *out, size_t cb) {
    if (!g_modsnap) modSnap();
    for (int i = 0; i < g_nmod; i++)
        if ((unsigned char *)ra >= g_mod[i].base && (unsigned char *)ra < g_mod[i].base + g_mod[i].sz) {
            _snprintf(out, cb - 1, "%s+0t%llX", Base(g_mod[i].name),
                      (unsigned long long)((unsigned char *)ra - g_mod[i].base));
            out[cb - 1] = 0; return;
        }
    _snprintf(out, cb - 1, "?%p", ra); out[cb - 1] = 0;
}
static void tsDel(void *p) {
    unsigned long long u = (unsigned long long)(size_t)p;
    u ^= u >> 16; u *= 0x9E3779B1u;
    unsigned i = (unsigned)(u >> 10) & (sizeof(g_ts) / sizeof(g_ts[0]) - 1);
    for (unsigned k = 0; k < 8; k++, i = (i + 1) & (sizeof(g_ts) / sizeof(g_ts[0]) - 1)) {
        if (!g_ts[i].p) return;
        if (g_ts[i].p == p) { g_ts[i].p = nullptr; return; }
    }
}
static HTS *tsFind(void *p) {
    unsigned long long u = (unsigned long long)(size_t)p;
    u ^= u >> 16; u *= 0x9E3779B1u;
    unsigned i = (unsigned)(u >> 10) & (sizeof(g_ts) / sizeof(g_ts[0]) - 1);
    for (unsigned k = 0; k < 8; k++, i = (i + 1) & (sizeof(g_ts) / sizeof(g_ts[0]) - 1)) {
        if (!g_ts[i].p) return nullptr;
        if (g_ts[i].p == p) return &g_ts[i];
    }
    return nullptr;
}
static void tsAdd(void *p, void *ra) {
    unsigned long long u = (unsigned long long)(size_t)p;
    u ^= u >> 16; u *= 0x9E3779B1u;
    unsigned i = (unsigned)(u >> 10) & (sizeof(g_ts) / sizeof(g_ts[0]) - 1);
    for (unsigned k = 0; k < 8; k++, i = (i + 1) & (sizeof(g_ts) / sizeof(g_ts[0]) - 1)) {
        if (!g_ts[i].p) { g_ts[i].p = p; g_ts[i].first_ra = ra; g_ts[i].nfree = 1; return; }
        if (g_ts[i].p == p) return;
    }
}
static unsigned char *g_hm1 = nullptr, *g_hm2 = nullptr;
static unsigned long long g_hlastp = 0;
static int g_hrep = 0;
static char g_hnames[512][132];
static int g_hnn = 0;
static void *STDAPICALLTYPE HookMalloc2(size_t n);
typedef void *(STDAPICALLTYPE *PFN_CALLOC)(size_t, size_t);
typedef void *(STDAPICALLTYPE *PFN_REALLOC)(void *, size_t);
typedef void *(STDAPICALLTYPE *PFN_MALLOC2)(size_t);
static void *g_orMalloc = nullptr, *g_orCalloc = nullptr, *g_orRealloc = nullptr;
static int g_guard = 0;
static void *GuardAlloc(size_t n);
static int GuardFree(void *p);
static void *GuardRealloc(void *b, size_t n);
static void GuardStat(void);

static unsigned hslot(void *p) {
    unsigned long long u = (unsigned long long)(size_t)p;
    u ^= u >> 16; u *= 0x9E3779B1u; return (unsigned)(u >> 10) & (sizeof(g_hs) / sizeof(g_hs[0]) - 1);
}
static void hAdd(void *p) {
    if (!p) return;
    tsDel(p);
    unsigned i = hslot(p);
    for (unsigned k = 0; k < 8; k++, i = (i + 1) & (sizeof(g_hs) / sizeof(g_hs[0]) - 1)) {
        if (!g_hs[i].p) { g_hs[i].p = p; g_hs[i].n = 1; g_hslive++; g_hsnew++; return; }
        if (g_hs[i].p == p) { g_hs[i].n++; return; }
    }
}
static int hDel(void *p) {                     // 1 = was live, 0 = not live
    if (!p) return 1;                          // free(NULL) is legal
    unsigned i = hslot(p);
    for (unsigned k = 0; k < 8; k++, i = (i + 1) & (sizeof(g_hs) / sizeof(g_hs[0]) - 1)) {
        if (g_hs[i].p == p) { if (--g_hs[i].n == 0) g_hs[i].p = nullptr; g_hslive--; return 1; }
        if (!g_hs[i].p) return 0;
    }
    return 0;
}
static unsigned long long hRva(void *ra) {
    if (g_hm1 && (unsigned char *)ra >= g_hm1 && (unsigned char *)ra < g_hm1 + 0x01000000ull)
        return (unsigned long long)((unsigned char *)ra - g_hm1);
    if (g_hm2 && (unsigned char *)ra >= g_hm2 && (unsigned char *)ra < g_hm2 + 0x01000000ull)
        return (unsigned long long)((unsigned char *)ra - g_hm2);
    return 0ull;
}
static void * STDAPICALLTYPE HookMalloc2(size_t n) {
    void *ra = _ReturnAddress();
    if (g_guard) {
        void *p = GuardAlloc(n);
        g_dfinhook = 1; hAdd(p); g_dfinhook = 0;
        return p;
    }
    void *p = g_orMalloc ? ((PFN_MALLOC2)g_orMalloc)(n) : nullptr;
    if (!g_dfinhook) { g_dfinhook = 1; hAdd(p); g_dfinhook = 0; }
    else hAdd(p);
    return p;
}
static void * STDAPICALLTYPE HookCalloc2(size_t c, size_t n) {
    void *ra = _ReturnAddress();
    if (g_guard) {
        size_t t;
        if (c && n > (SIZE_MAX / c)) return nullptr;          // same overflow answer the CRT gives
        t = c * n;
        void *p = GuardAlloc(t);
        g_dfinhook = 1; hAdd(p); g_dfinhook = 0;
        return p;
    }
    PFN_CALLOC f = (PFN_CALLOC)(void *)g_orCalloc;
    void *p = f ? f(c, n) : nullptr;
    if (!g_dfinhook) { g_dfinhook = 1; hAdd(p); g_dfinhook = 0; }
    else hAdd(p);
    return p;
}
static void * STDAPICALLTYPE HookRealloc2(void *b, size_t n) {
    void *ra = _ReturnAddress();
    if (g_guard) {
        void *p = GuardRealloc(b, n);
        g_dfinhook = 1; hDel(b); hAdd(p); g_dfinhook = 0;
        return p;
    }
    PFN_REALLOC f = (PFN_REALLOC)(void *)g_orRealloc;
    void *p = f ? f(b, n) : nullptr;
    if (!g_dfinhook) { g_dfinhook = 1; hDel(b); hAdd(p); g_dfinhook = 0; }
    else { hDel(b); hAdd(p); }
    return p;
}
// A tail-guard allocator that replaces the CRT one through the same observed slots.
// IFEO page heap (GlobalFlag=0x200) was tried first and the in-bounds/+0x100 positive control did not
// fault, so it cannot be relied on here; this one is armed by the same code that hands the blocks out,
// so its own control proves the guard page is where the end of the request is.
// Layout: [metadata page][data pages ...][NOACCESS page], with the returned pointer placed so that
// user + n lands exactly on the guard page - the first byte written past the end faults.
static size_t g_pgfb = 0, g_pgn = 0, g_pgmax = 0, g_pgcur = 0, g_pgif = 0;
struct PG { void *user; void *base; size_t total; size_t n; };
static PG g_pg[1 << 18];
static unsigned pgs(void *u) {
    unsigned long long x = (unsigned long long)(size_t)u;
    x ^= x >> 13; x *= 0x9E3779B97F4A7C15ull; return (unsigned)(x >> 26) & (sizeof(g_pg) / sizeof(g_pg[0]) - 1);
}
static void pgPut(void *u, void *base, size_t total, size_t n) {
    unsigned i = pgs(u);
    for (unsigned k = 0; k < 8; k++, i = (i + 1) & (sizeof(g_pg) / sizeof(g_pg[0]) - 1)) {
        if (!g_pg[i].user) { g_pg[i].user = u; g_pg[i].base = base; g_pg[i].total = total; g_pg[i].n = n; return; }
    }
    g_pgif++;                       // table full: the block is still guard-owned, free() will leak it
}
static PG *pgGet(void *u) {
    if (!u) return nullptr;
    unsigned i = pgs(u);
    for (unsigned k = 0; k < 8; k++, i = (i + 1) & (sizeof(g_pg) / sizeof(g_pg[0]) - 1)) {
        if (!g_pg[i].user) return nullptr;
        if (g_pg[i].user == u) return &g_pg[i];
    }
    return nullptr;
}
static void pgDel(void *u) {
    unsigned i = pgs(u);
    for (unsigned k = 0; k < 8; k++, i = (i + 1) & (sizeof(g_pg) / sizeof(g_pg[0]) - 1)) {
        if (!g_pg[i].user) return;
        if (g_pg[i].user == u) { g_pg[i].user = nullptr; g_pg[i].base = nullptr; return; }
    }
}
static void *GuardAlloc(size_t n) {
    if (!n) n = 1;
    size_t dataPg = (n + 0xFFF) / 0x1000;
    size_t total = (1 + dataPg + 1) * 0x1000;
    unsigned char *b = (unsigned char *)VirtualAlloc(nullptr, total, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!b) { g_pgfb++; return g_orMalloc ? ((PFN_MALLOC2)g_orMalloc)(n) : nullptr; }
    DWORD op = 0;
    VirtualProtect(b + (1 + dataPg) * 0x1000, 0x1000, PAGE_NOACCESS, &op);
    void *user = b + (1 + dataPg) * 0x1000 - n;
    pgPut(user, b, total, n);
    g_pgn++; g_pgcur++;
    if (g_pgcur > g_pgmax) g_pgmax = g_pgcur;
    return user;
}
static int GuardFree(void *p) {               // 1 = this block was guard-owned and is released
    PG *e = pgGet(p);
    if (!e) return 0;
    void *base = e->base;
    pgDel(p);
    g_pgcur--;
    if (base) VirtualFree(base, 0, MEM_RELEASE);
    return 1;
}
static void *GuardRealloc(void *b, size_t n) {
    PG *e = pgGet(b);
    if (!e) return g_orRealloc ? ((PFN_REALLOC)(void *)g_orRealloc)(b, n) : nullptr;
    void *p = GuardAlloc(n);
    if (p && n) memcpy(p, b, e->n < n ? e->n : n);   // copy the old contents, never past the old end
    GuardFree(b);
    return p;
}
static void GuardStat(void) {
    printf("GUARDSTAT allocs=%zu live=%zu peak=%zu crt_fallback=%zu table_full=%zu\n",
           g_pgn, g_pgcur, g_pgmax, g_pgfb, g_pgif); fflush(stdout);
}

static void STDAPICALLTYPE HookFree2(void *p) {
    void *ra = _ReturnAddress();
    if (!g_dfinhook) {
        g_dfinhook = 1;
        if (hDel(p)) {
            if (p) tsAdd(p, ra);
        } else {
            g_hsnfun++;
            HTS *t = tsFind(p);
            char b1[300], b2[300];
            if (t) {
                t->nfree++;
                g_tsdup++;
                sAdd(g_dupsite, &g_ndup, ra);
                if (g_tduprep < 60) {
                    g_tduprep++;
                    raTxt(t->first_ra, b1, sizeof(b1));
                    raTxt(ra, b2, sizeof(b2));
                    printf("DUPFREE p=%p first=%s again=%s n=%u (live=%u)\n",
                           p, b1, b2, t->nfree, g_hslive); fflush(stdout);
                }
            } else {
                g_tsunt++;
                sAdd(g_untsite, &g_nunt, ra);
                if (g_hrep < 40) {
                    g_hrep++;
                    raTxt(ra, b2, sizeof(b2));
                    printf("UNTRACKED free p=%p at=%s (live=%u)\n", p, b2, g_hslive); fflush(stdout);
                }
            }
        }
        g_dfinhook = 0;
    }
    if (!(g_guard && GuardFree(p)) && g_dfreal) g_dfreal(p);
}

// Point a module's own allocator imports at the observers above. Returns how many slots were taken.
static void HookStat(void) {
    char b[300];
    GuardStat();
    printf("HOOKSTAT live=%u new=%u notlive=%u dup=%u untracked=%u\n",
           g_hslive, g_hsnew, g_hsnfun, g_tsdup, g_tsunt);
    for (int i = 0; i < g_ndup; i++) {
        raTxt(g_dupsite[i].ra, b, sizeof(b));
        printf("DUPSITE %s n=%u\n", b, g_dupsite[i].n);
    }
    for (int i = 0; i < g_nunt; i++) {
        raTxt(g_untsite[i].ra, b, sizeof(b));
        printf("UNTSITE %s n=%u\n", b, g_untsite[i].n);
    }
    fflush(stdout);
}
static int InstallAllocHooks(const char *modname, int which) {
    // "self" hooks this host's own imports - used as the detector's positive control, so a run that
    // reports nothing can be told apart from a detector that never saw the release at all.
    // One install per module: chaining two copies of the observer makes the outer one report the
    // inner one's own return address as an unknown caller. Leaving a module unhooked is the opposite
    // failure - memory it allocated through its own slots is then released by a hooked module and
    // looks like a release of untracked memory - so every module that can hand out or give back
    // blocks has to be observed, which is what "all" does for the Office modules in the process.
    if (!_stricmp(modname, "all")) {
        modSnap();
        unsigned char *exebase = (unsigned char *)GetModuleHandleA(nullptr);
        int tot = 0, nm = 0;
        for (int i = 0; i < g_nmod; i++) {
            const char *bn = Base(g_mod[i].name);
            if (!_stricmp(bn, "ucrtbase.dll") || !_stricmp(bn, "msvcrt.dll")
                || !_stricmp(bn, "ntdll.dll") || !_stricmp(bn, "kernel32.dll")
                || !_stricmp(bn, "kernelbase.dll")) continue;
            int office = !_strnicmp(g_mod[i].path, "C:\\Program Files\\Microsoft Office\\Root\\", 34);
            if (!office && g_mod[i].base != exebase) continue;
            tot += InstallAllocHooks(g_mod[i].name, 1);
            nm++;
        }
        printf("HOOKALL modules=%d slots=%d\n", nm, tot); fflush(stdout);
        return tot;
    }
    for (int q = 0; q < g_hnn; q++) if (!_stricmp(g_hnames[q], modname)) return 0;
    if (g_hnn < 512) { strncpy(g_hnames[g_hnn], modname, 131); g_hnames[g_hnn][131] = 0; g_hnn++; }
    HMODULE hm = !_stricmp(modname, "self") ? (HMODULE)GetModuleHandleA(nullptr) : GetModuleHandleA(modname);
    if (!hm) hm = LoadLibraryExA(modname, nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!hm) {
        char pp[512];
        _snprintf(pp, sizeof(pp) - 1, "C:\\Program Files\\Microsoft Office\\root\\Office16\\%s", modname);
        pp[sizeof(pp) - 1] = 0;
        hm = LoadLibraryExA(pp, nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    }
    if (!hm) { printf("HOOKMOD_ABSENT %s\n", modname); fflush(stdout); return 0; }
    IMAGE_DOS_HEADER *d = (IMAGE_DOS_HEADER *)hm;
    IMAGE_NT_HEADERS64 *n = (IMAGE_NT_HEADERS64 *)((char *)hm + d->e_lfanew);
    IMAGE_DATA_DIRECTORY *i = &n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!i->Size) return 0;
    int got = 0;
    for (IMAGE_IMPORT_DESCRIPTOR *ip = (IMAGE_IMPORT_DESCRIPTOR *)((char *)hm + i->VirtualAddress);
         ip && ip->Name; ip++) {
        const char *dn = (const char *)hm + ip->Name;
        // Only the modern CRT is observed: msvcrt.dll has its own heap, and pointing both CRTs' slots
        // at one shared "original" trampoline would free a block through the allocator that did not
        // hand it out. Releases made through msvcrt are therefore outside the observer's view.
        if (_stricmp(dn, "api-ms-win-crt-heap-l1-1-0.dll") && _stricmp(dn, "ucrtbase.dll")) continue;
        if (!ip->FirstThunk || !ip->OriginalFirstThunk) continue;
        IMAGE_THUNK_DATA64 *ft = (IMAGE_THUNK_DATA64 *)((char *)hm + ip->FirstThunk);
        IMAGE_THUNK_DATA64 *it = (IMAGE_THUNK_DATA64 *)((char *)hm + ip->OriginalFirstThunk);
        for (unsigned j = 0; it[j].u1.AddressOfData; j++) {
            if (it[j].u1.Ordinal & IMAGE_ORDINAL_FLAG64) continue;
            IMAGE_IMPORT_BY_NAME *ib = (IMAGE_IMPORT_BY_NAME *)((char *)hm + it[j].u1.AddressOfData);
            const char *nm = (const char *)ib->Name;
            void **slot = (void **)&ft[j].u1.AddressOfData;
            void *target = nullptr;
            if (!strcmp(nm, "malloc")) { target = (void *)&HookMalloc2; g_orMalloc = (PFN_MALLOC2)*slot; }
            else if (!strcmp(nm, "calloc")) { target = (void *)&HookCalloc2; g_orCalloc = (PFN_CALLOC)*slot; }
            else if (!strcmp(nm, "realloc")) { target = (void *)&HookRealloc2; g_orRealloc = (PFN_REALLOC)*slot; }
            else if (!strcmp(nm, "free")) { target = (void *)&HookFree2; g_dfreal = (PFN_FREE_T)*slot; }
            if (!target) continue;
            DWORD op = 0;
            if (VirtualProtect(slot, 8, PAGE_READWRITE, &op)) {
                if (which == 1 && !g_hm1) g_hm1 = (unsigned char *)hm;
                else if (which == 2 && !g_hm2) g_hm2 = (unsigned char *)hm;
                *slot = target;
                VirtualProtect(slot, 8, op, &op);
                got++;
            }
        }
    }
    printf("HOOK %s base=%p slots=%d malloc=%p calloc=%p realloc=%p free=%p\n", modname, (void *)hm, got,
           (void *)g_orMalloc, (void *)g_orCalloc, (void *)g_orRealloc, (void *)g_dfreal); fflush(stdout);
    return got;
}

int main(int argc, char **argv)
{
    if (argc < 2) { printf("usage: crtfbench <blob|-> [flags-hex] [readchunk] [mode]\n"); return 2; }
    setvbuf(stdout, nullptr, _IONBF, 0);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    DWORD wms = (argc > 5) ? (DWORD)atoi(argv[5]) : 20000;
    if (wms) { HANDLE hT = CreateThread(nullptr, 0, Watchdog, (LPVOID)(ULONG_PTR)wms, 0, nullptr); if (hT) CloseHandle(hT); }
    AddVectoredExceptionHandler(1, Veh);
    char exe[MAX_PATH]; GetModuleFileNameA(nullptr, exe, sizeof(exe));
    printf("host=%s bits=%d\n", Base(exe), (int)(sizeof(void *) * 8));
    atexit(HookStat);
    g_guard = getenv("CRTF_GUARD") ? atoi(getenv("CRTF_GUARD")) : 0;

    g_hOlm = LoadLibraryExA("OLMAPI32.dll", nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!g_hOlm) {
        // fall back to the absolute in-service path
        g_hOlm = LoadLibraryExA("C:\\Program Files\\Microsoft Office\\root\\Office16\\OLMAPI32.dll",
                                nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    }
    if (!g_hOlm) { printf("LOADERR olmaapi32 gle=%lu\n", GetLastError()); return 3; }
    ModuleFor((uintptr_t)g_hOlm, g_modname, sizeof(g_modname), &g_modbase);
    printf("olm=%s base=%p\n", Base(g_modname), (void *)g_modbase);
    g_pWrap = (PFN_WRAP)GetProcAddress(g_hOlm, "WrapCompressedRTFStream");
    g_pWrapEx = (PFN_WRAP)GetProcAddress(g_hOlm, "WrapCompressedRTFStreamEx");
    PFN_MAPIINIT pInit = (PFN_MAPIINIT)GetProcAddress(g_hOlm, "MAPIInitialize");
    if (!g_pWrap) { printf("NOWRAP\n"); return 4; }
    // The observer has to be in place before the module allocates anything at all: with the install
    // after MAPIInitialize, every block that initialisation produced looks like a release of memory
    // the observer never handed out, and that noise hides the signal the observer exists to find.
    if (argc > 4 && atoi(argv[4]) == 52) {
        char buf0[512];
        strncpy(buf0, getenv("CRTF_MODS") ? getenv("CRTF_MODS") : "OLMAPI32.dll;OUTLMIME.dll", sizeof(buf0) - 1);
        buf0[sizeof(buf0) - 1] = 0;
        int w0 = 1;
        for (char *tk = strtok(buf0, ";"); tk && w0 <= 2; tk = strtok(nullptr, ";")) { InstallAllocHooks(tk, w0); w0++; }
    }
    if (pInit && !getenv("CRTF_NOMAPI")) { HRESULT hr = pInit(nullptr); printf("MAPIInitialize hr=%08x\n", (unsigned)hr); }
    else printf("MAPIInitialize skipped\n");

    if (argc > 1 && strcmp(argv[1], "selftest") == 0) {
        // armed-heap gate: in-bounds write must pass, +0x100 write must fault (0xC0000005)
        printf("BEGIN\n"); fflush(stdout);
        HANDLE hp = GetProcessHeap();
        char *p1 = (char *)HeapAlloc(hp, 0, 0x100);
        printf("ALLOC addr=%p\n", (void *)p1); fflush(stdout);
        for (int i = 0; i < 0x100; i++) p1[i] = (char)i;
        printf("INBOUNDS_OK\n"); fflush(stdout);
        printf("ABOUT_TO_WRITE_PAST_END\n"); fflush(stdout);
        p1[0x100] = 0x41;
        printf("NOT_DETECTED p1[0x100]=%02x\n", (unsigned char)p1[0x100]); fflush(stdout);
        return 0;
    }
    ULONG flags = (argc > 2) ? (ULONG)strtoul(argv[2], nullptr, 16) : 0;
    ULONG chunk = (argc > 3) ? (ULONG)strtoul(argv[3], nullptr, 10) : 0x100;
    int mode = (argc > 4) ? atoi(argv[4]) : 0;




    if (mode == 52) {
        // Install the allocator observers on the named modules, then hand control to the driver named
        // by CRTF_RUN so an existing file-fed corpus runs under them.
        char buf[256];
        strncpy(buf, getenv("CRTF_MODS") ? getenv("CRTF_MODS") : "OLMAPI32.dll;OUTLMIME.dll", sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = 0;
        int w = 1;
        for (char *tk = strtok(buf, ";"); tk && w <= 2; tk = strtok(nullptr, ";")) { InstallAllocHooks(tk, w); w++; }
        int cont = getenv("CRTF_RUN") ? atoi(getenv("CRTF_RUN")) : 11;
        printf("HOOKED continue_mode=%d\n", cont); fflush(stdout);
        mode = cont;
    }

    if (mode == 22) {
        // Stateful sequence: every .msg carrier in a directory is opened, its compressed-RTF body
        // is decoded and the exported RTFSync rewrite runs -- all inside ONE process, so MAPI heap
        // blocks freed by carrier N are reallocated with carrier N+1's data (the cross-carrier
        // reuse a fresh process per case cannot exercise).
        HMODULE hl2 = GetModuleHandleA("OLMAPI32.dll");
        PFN_RTFSYNC pSync2 = (PFN_RTFSYNC)GetProcAddress(hl2, "RTFSync");
        PFN_OPENMSGSESS pSess2 = (PFN_OPENMSGSESS)GetProcAddress(hl2, "OpenIMsgSession");
        PFN_OPENMSGONI pOpen2 = (PFN_OPENMSGONI)GetProcAddress(hl2, "OpenIMsgOnIStg");
        PFN_ALLOCBUF pAB2 = (PFN_ALLOCBUF)GetProcAddress(hl2, "MAPIAllocateBuffer");
        PFN_ALLOCMORE pAM2 = (PFN_ALLOCMORE)GetProcAddress(hl2, "MAPIAllocateMore");
        PFN_FREEBUF pFB2 = (PFN_FREEBUF)GetProcAddress(hl2, "MAPIFreeBuffer");
        if (!pSync2 || !pSess2 || !pOpen2) { printf("SEQEXPORTS\n"); return 12; }
        char pat[1100];
        size_t bl0 = strlen(argv[1]);
        _snprintf(pat, sizeof(pat) - 1, "%s%s*.msg", argv[1],
                  (bl0 && argv[1][bl0 - 1] == '\\') ? "" : "\\");
        WIN32_FIND_DATAA fd;
        HANDLE hF = FindFirstFileA(pat, &fd);
        if (hF == INVALID_HANDLE_VALUE) { printf("NOFILES\n"); return 13; }
        IMalloc *pMalloc2 = nullptr;
        HRESULT hci = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        HRESULT hcm = CoGetMalloc(MEMCTX_TASK, &pMalloc2);
        printf("SEQCO init=%08x malloc=%08x p=%p\n", (unsigned)hci, (unsigned)hcm, (void *)pMalloc2);
        fflush(stdout);
        if (!pMalloc2) { printf("SEQNO_MALLOC\n"); return 14; }
        void *pSession2 = nullptr;
        HRESULT hss = pSess2((void *)pMalloc2, 0, &pSession2);
        printf("SEQSESS=%08x p=%p\n", (unsigned)hss, pSession2); fflush(stdout);
        unsigned long cnt = 0, opened2 = 0, syncs = 0, ups = 0;
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            if (fd.cFileName[0] == '.' || fd.cFileName[0] == '_') continue;  /* AppleDouble ._x / scratch */
            char full[1200];
            size_t bl = strlen(argv[1]);
            _snprintf(full, sizeof(full) - 1, "%s%s%s", argv[1],
                      (bl && argv[1][bl - 1] == '\\') ? "" : "\\", fd.cFileName);
            cnt++;
            IStorage *pStg2 = nullptr;
            WCHAR wp2[1100];
            MultiByteToWideChar(CP_ACP, 0, full, -1, wp2, 1090);
            HRESULT h3 = StgOpenStorageEx(wp2, STGM_READ | STGM_SHARE_DENY_WRITE, STGFMT_STORAGE, 0,
                                          nullptr, nullptr, __uuidof(IStorage), (void **)&pStg2);
            if (SUCCEEDED(h3) && pStg2) {
                void *pMsg2 = nullptr;
                h3 = pOpen2(pSession2, (void *)pAB2, (void *)pAM2, (void *)pFB2, pMalloc2, nullptr,
                            pStg2, nullptr, 0, 0, &pMsg2);
                if (SUCCEEDED(h3) && pMsg2) {
                    opened2++;
                    for (ULONG fl = 1; fl <= 3; fl++) {
                        int upd = -1;
                        HRESULT h4 = pSync2(pMsg2, fl, &upd);
                        if (SUCCEEDED(h4)) { syncs++; if (upd) ups++; }
                    }
                    printf("CARRIER %lu %s released\n", cnt, fd.cFileName); fflush(stdout);
                    ((ULONG (STDMETHODCALLTYPE *)(void *))*(void **)*((void **)pMsg2 + 2))(pMsg2);
                }
                pStg2->Release();
            }
            if ((cnt % 100) == 0) { printf("SEQ %lu opened=%lu syncs=%lu updated=%lu\n", cnt, opened2, syncs, ups); fflush(stdout); }
        } while (FindNextFileA(hF, &fd));
        FindClose(hF);
        printf("SEQEND carriers=%lu opened=%lu syncs=%lu updated=%lu\n", cnt, opened2, syncs, ups);
        fflush(stdout);
        return 0;
    }
    if (mode == 23) {
        // Staged, slot-verified version of mode 22. Every step prints a checkpoint before it runs,
        // and the IMessage Release slot is checked to be an address inside OLMAPI32 before it is
        // called (mode 22's hand-coded slot call double-dereferenced and jumped into a vtable).
        HMODULE hl3 = GetModuleHandleA("OLMAPI32.dll");
        PFN_RTFSYNC pSync3 = (PFN_RTFSYNC)GetProcAddress(hl3, "RTFSync");
        PFN_OPENMSGSESS pSess3 = (PFN_OPENMSGSESS)GetProcAddress(hl3, "OpenIMsgSession");
        PFN_OPENMSGONI pOpen3 = (PFN_OPENMSGONI)GetProcAddress(hl3, "OpenIMsgOnIStg");
        PFN_ALLOCBUF pAB3 = (PFN_ALLOCBUF)GetProcAddress(hl3, "MAPIAllocateBuffer");
        PFN_ALLOCMORE pAM3 = (PFN_ALLOCMORE)GetProcAddress(hl3, "MAPIAllocateMore");
        PFN_FREEBUF pFB3 = (PFN_FREEBUF)GetProcAddress(hl3, "MAPIFreeBuffer");
        if (!pSync3 || !pSess3 || !pOpen3) { printf("SEQEXPORTS\n"); return 12; }
        ULONG textLo = 0, textHi = 0;
        {
            IMAGE_DOS_HEADER *dh = (IMAGE_DOS_HEADER *)hl3;
            IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((BYTE *)hl3 + dh->e_lfanew);
            textLo = (ULONG)nt->OptionalHeader.BaseOfCode;
            textHi = textLo + nt->OptionalHeader.SizeOfCode;
            printf("STEP0 olm_text_rva=0x%X-0x%X\n", textLo, textHi); fflush(stdout);
        }
        char pat3[1100];
        size_t bl3 = strlen(argv[1]);
        _snprintf(pat3, sizeof(pat3) - 1, "%s%s*.msg", argv[1],
                  (bl3 && argv[1][bl3 - 1] == '\\') ? "" : "\\");
        WIN32_FIND_DATAA fd;
        HANDLE hF = FindFirstFileA(pat3, &fd);
        if (hF == INVALID_HANDLE_VALUE) { printf("NOFILES\n"); return 13; }
        IMalloc *pMalloc3 = nullptr;
        printf("STEP1 CoGetMalloc hr=%08x\n", (unsigned)CoGetMalloc(MEMCTX_TASK, &pMalloc3)); fflush(stdout);
        void *pSession3 = nullptr;
        HRESULT hs3 = pSess3((void *)pMalloc3, 0, &pSession3);
        printf("STEP2 OpenIMsgSession hr=%08x sess=%p\n", (unsigned)hs3, pSession3); fflush(stdout);
        unsigned long cnt = 0, opened3 = 0, syncs = 0, ups = 0, rels = 0, badslot = 0;
        unsigned long maxc = getenv("CRTF_MAX") ? strtoul(getenv("CRTF_MAX"), nullptr, 10) : 0;
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            if (fd.cFileName[0] == '.' || fd.cFileName[0] == '_') continue;  /* AppleDouble ._x / scratch */
            if (maxc && cnt >= maxc) break;
            char full[1200];
            _snprintf(full, sizeof(full) - 1, "%s%s%s", argv[1],
                      (bl3 && argv[1][bl3 - 1] == '\\') ? "" : "\\", fd.cFileName);
            cnt++;
            IStorage *pStg3 = nullptr;
            WCHAR wp3[1100];
            MultiByteToWideChar(CP_ACP, 0, full, -1, wp3, 1090);
            HRESULT h3 = StgOpenStorageEx(wp3, STGM_READ | STGM_SHARE_DENY_WRITE, STGFMT_STORAGE, 0,
                                          nullptr, nullptr, __uuidof(IStorage), (void **)&pStg3);
            if (FAILED(h3) || !pStg3) { printf("OPENFAIL %s hr=%08x\n", fd.cFileName, (unsigned)h3); continue; }
            void *pMsg3 = nullptr;
            h3 = pOpen3(pSession3, (void *)pAB3, (void *)pAM3, (void *)pFB3, pMalloc3, nullptr,
                        pStg3, nullptr, 0, 0, &pMsg3);
            if (FAILED(h3) || !pMsg3) { printf("MSGFAIL %s hr=%08x\n", fd.cFileName, (unsigned)h3);
                                        pStg3->Release(); continue; }
            opened3++;
            void **vtbl = (void **)pMsg3;
            void **slots = (void **)vtbl[0];
            uintptr_t vtRva = (uintptr_t)slots - (uintptr_t)hl3;
            void *relFn = slots[2];
            uintptr_t relRva = (uintptr_t)relFn - (uintptr_t)hl3;
            printf("MSG %lu %s obj=%p vtbl_rva=0x%llX rel_rva=0x%llX\n", cnt, fd.cFileName,
                   pMsg3, (unsigned long long)vtRva, (unsigned long long)relRva); fflush(stdout);
            if ((uintptr_t)relFn < (uintptr_t)hl3 + textLo || (uintptr_t)relFn > (uintptr_t)hl3 + textHi) {
                badslot++;
                printf("BAD_SLOT %lu rel=%p outside .text -- skipping call\n", cnt, relFn); fflush(stdout);
                pStg3->Release();
                continue;
            }
            for (ULONG fl = 1; fl <= 3; fl++) {
                int upd = -1;
                HRESULT h4 = pSync3(pMsg3, fl, &upd);
                if (SUCCEEDED(h4)) { syncs++; if (upd) ups++; }
            }
            PFN_RELEASE pRel = (PFN_RELEASE)relFn;
            ULONG rc = pRel(pMsg3);
            rels++;
            printf("RELEASED %lu %s ref=%lu\n", cnt, fd.cFileName, rc); fflush(stdout);
            pStg3->Release();
            if ((cnt % 100) == 0) printf("SEQ %lu opened=%lu syncs=%lu updated=%lu rels=%lu bad=%lu\n",
                                         cnt, opened3, syncs, ups, rels, badslot);
        } while (FindNextFileA(hF, &fd));
        FindClose(hF);
        printf("SEQEND carriers=%lu opened=%lu syncs=%lu updated=%lu rels=%lu bad=%lu\n",
               cnt, opened3, syncs, ups, rels, badslot);
        fflush(stdout);
        return 0;
    }
    if (mode == 24) {
        // Interleaved live objects: hold K IMessage objects open at once, run every RTFSync pass after
        // all K are allocated, then release in reverse order. Exercises the allocator pattern where
        // carrier N's chunk buffers are still live while carrier N+1 grows its own.
        HMODULE hl4 = GetModuleHandleA("OLMAPI32.dll");
        PFN_RTFSYNC pSync4 = (PFN_RTFSYNC)GetProcAddress(hl4, "RTFSync");
        PFN_OPENMSGSESS pSess4 = (PFN_OPENMSGSESS)GetProcAddress(hl4, "OpenIMsgSession");
        PFN_OPENMSGONI pOpen4 = (PFN_OPENMSGONI)GetProcAddress(hl4, "OpenIMsgOnIStg");
        PFN_ALLOCBUF pAB4 = (PFN_ALLOCBUF)GetProcAddress(hl4, "MAPIAllocateBuffer");
        PFN_ALLOCMORE pAM4 = (PFN_ALLOCMORE)GetProcAddress(hl4, "MAPIAllocateMore");
        PFN_FREEBUF pFB4 = (PFN_FREEBUF)GetProcAddress(hl4, "MAPIFreeBuffer");
        if (!pSync4 || !pSess4 || !pOpen4) { printf("SEQEXPORTS\n"); return 12; }
        ULONG textLo4 = 0, textHi4 = 0;
        {
            IMAGE_DOS_HEADER *dh = (IMAGE_DOS_HEADER *)hl4;
            IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((BYTE *)hl4 + dh->e_lfanew);
            textLo4 = (ULONG)nt->OptionalHeader.BaseOfCode;
            textHi4 = textLo4 + nt->OptionalHeader.SizeOfCode;
        }
        unsigned long K = getenv("CRTF_K") ? strtoul(getenv("CRTF_K"), nullptr, 10) : 8;
        if (K < 2) K = 2;
        if (K > 256) K = 256;
        char pat4[1100];
        size_t bl4 = strlen(argv[1]);
        _snprintf(pat4, sizeof(pat4) - 1, "%s%s*.msg", argv[1],
                  (bl4 && argv[1][bl4 - 1] == '\\') ? "" : "\\");
        WIN32_FIND_DATAA fd;
        HANDLE hF = FindFirstFileA(pat4, &fd);
        if (hF == INVALID_HANDLE_VALUE) { printf("NOFILES\n"); return 13; }
        IMalloc *pMalloc4 = nullptr;
        CoGetMalloc(MEMCTX_TASK, &pMalloc4);
        void *pSession4 = nullptr;
        printf("SESS hr=%08x\n", (unsigned)pSess4((void *)pMalloc4, 0, &pSession4)); fflush(stdout);
        struct Slot { IStorage *stg; void *msg; char name[260]; };
        Slot *slots = (Slot *)calloc(K, sizeof(Slot));
        char (*files)[260] = (char(*)[260])malloc(4096u * 260);
        unsigned long nf = 0;
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            if (fd.cFileName[0] == '.' || fd.cFileName[0] == '_') continue;  /* AppleDouble ._x / scratch */
            if (nf >= 4096) break;
            strncpy(files[nf], fd.cFileName, 259);
            files[nf][259] = 0;
            nf++;
        } while (FindNextFileA(hF, &fd));
        FindClose(hF);
        unsigned long total = 0, syncs = 0, ups = 0, rels = 0, bad = 0, rounds = 0;
        unsigned long maxc = getenv("CRTF_MAX") ? strtoul(getenv("CRTF_MAX"), nullptr, 10) : 0;
        if (maxc && maxc < nf) nf = maxc;
        for (unsigned long base = 0; base < nf; base += K) {
            unsigned long live = 0;
            for (unsigned long i = base; i < nf && live < K; i++) {
                char full[1300];
                _snprintf(full, sizeof(full) - 1, "%s%s%s", argv[1],
                          (bl4 && argv[1][bl4 - 1] == '\\') ? "" : "\\", files[i]);
                total++;
                WCHAR wp4[1100];
                MultiByteToWideChar(CP_ACP, 0, full, -1, wp4, 1090);
                IStorage *stg = nullptr;
                HRESULT h4 = StgOpenStorageEx(wp4, STGM_READ | STGM_SHARE_DENY_WRITE, STGFMT_STORAGE,
                                              0, nullptr, nullptr, __uuidof(IStorage), (void **)&stg);
                if (FAILED(h4) || !stg) continue;
                void *msg = nullptr;
                h4 = pOpen4(pSession4, (void *)pAB4, (void *)pAM4, (void *)pFB4, pMalloc4, nullptr,
                            stg, nullptr, 0, 0, &msg);
                if (FAILED(h4) || !msg) continue;
                void **vt = (void **)*((void ***)msg);
                if ((uintptr_t)vt[2] < (uintptr_t)hl4 + textLo4
                    || (uintptr_t)vt[2] > (uintptr_t)hl4 + textHi4) {
                    bad++;
                    printf("BAD_SLOT %s vt0_rva=0x%llX rel_rva=0x%llX\n", files[i],
                           (unsigned long long)((uintptr_t)vt - (uintptr_t)hl4),
                           (unsigned long long)((uintptr_t)vt[2] - (uintptr_t)hl4)); fflush(stdout);
                    continue;
                }
                slots[live].stg = stg;
                slots[live].msg = msg;
                strncpy(slots[live].name, files[i], 259);
                live++;
            }
            if (!live) continue;
            rounds++;
            printf("ROUND %lu live=%lu\n", rounds, live); fflush(stdout);
            for (ULONG pass = 0; pass < 3; pass++) {
                for (unsigned long i = 0; i < live; i++) {
                    int upd = -1;
                    HRESULT h5 = pSync4(slots[i].msg, 2, &upd);
                    if (SUCCEEDED(h5)) { syncs++; if (upd) ups++; }
                }
            }
            for (unsigned long i = live; i-- > 0;) {
                void **vt = (void **)*((void ***)slots[i].msg);
                ((PFN_RELEASE)vt[2])(slots[i].msg);
                rels++;
                slots[i].stg->Release();
                slots[i].msg = nullptr;
                slots[i].stg = nullptr;
            }
        }
        printf("ILVEND carriers=%lu files=%lu rounds=%lu syncs=%lu updated=%lu rels=%lu bad=%lu\n",
               total, nf, rounds, syncs, ups, rels, bad); fflush(stdout);
        return 0;
    }
    if (mode == 41) {
        // OUTLMIME!DecodeAttrSequenceEx with a CALLER-SUPPLIED buffer (flags & 0x8000 == 0 forwards
        // straight to the inner decoder at 0x18000A618). Ask the API for the size it needs, then give
        // it exactly that many bytes from the armed heap: any write past the declared capacity trips
        // the page guard and is attributed to the module + RVA.
        g_soft = 1;
        HMODULE hm1 = LoadLibraryExA("OUTLMIME.dll", nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!hm1) hm1 = LoadLibraryExA("C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLMIME.dll",
                                       nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        PFN_DASEX pDas = (PFN_DASEX)GetProcAddress(hm1, "DecodeAttrSequenceEx");
        printf("OUTLMIME=%p das=%p\n", (void *)hm1, (void *)pDas); fflush(stdout);
        if (!pDas) { printf("NODAS\n"); return 10; }
        size_t fsz = 0; BYTE *fb = LoadBlob(argv[1], &fsz);
        if (!fb) { printf("NOINPUT\n"); return 11; }
        size_t off = 0; unsigned long n = 0, qok = 0, fok = 0, skips = 0;
        unsigned long nmax = getenv("CRTF_NMAX") ? strtoul(getenv("CRTF_NMAX"), nullptr, 10) : 200000;
        while (off + 1 < fsz && n < nmax) {
            size_t e1 = off; while (e1 < fsz && fb[e1] != '\n') e1++;
            if (e1 >= fsz) break;
            long want = strtol((char *)fb + off, nullptr, 10);
            size_t body = e1 + 1;
            if (want <= 0 || body + (size_t)want > fsz) break;
            off = body + want;
            if (off < fsz && fb[off] == '\n') off++;
            ULONG need = 0;
            BOOL ok = 0;
            __try {
                ok = pDas(0, nullptr, fb + body, (ULONG)want, 0, nullptr, nullptr, &need);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                printf("FAULTQ rec=%lu len=%ld code=%08x\n", n, want, (unsigned)GetExceptionCode());
                n++; continue;
            }
            printf("QR n=%lu len=%ld q=%u need=%lu gle=%u\n", n, want, (unsigned)ok, need,
                   (unsigned)GetLastError()); fflush(stdout);
            if (!ok || !need || need > (64u << 20)) { skips++; n++; continue; }
            qok++;
            unsigned long deltas[3] = { 0, 8, 64 };
            for (int d = 0; d < 3; d++) {
                ULONG cap = need + deltas[d];
                BYTE *dst = (BYTE *)malloc(cap);
                if (!dst) continue;
                memset(dst, 0xCC, cap);
                ULONG cb = cap;
                BOOL ok2 = 0;
                __try {
                    ok2 = pDas(0, nullptr, fb + body, (ULONG)want, 0, nullptr, dst, &cb);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    printf("FAULTR rec=%lu len=%ld need=%lu d=%lu code=%08x\n", n, want, need, deltas[d],
                           (unsigned)GetExceptionCode());
                    fflush(stdout);
                }
                printf("  FILL n=%lu d=%lu cap=%lu r=%u cb=%lu gle=%u\n", n, deltas[d], cap,
                       (unsigned)ok2, cb, (unsigned)GetLastError()); fflush(stdout);
                if (ok2) fok++;
                free(dst);
            }
            if ((n % 25) == 0) printf("PROG %lu qok=%lu fok=%lu skip=%lu rec_len=%ld need=%lu\n",
                                      n, qok, fok, skips, want, need);
            n++;
        }
        printf("ATTRCASES n=%lu qok=%lu fok=%lu skip=%lu faults=%lu\n", n, qok, fok, skips, g_faults);
        fflush(stdout);
        return 0;
    }
    if (mode == 42) {
        // OUTLMIME's seven Ess*DecodeEx entry points driven from a DER corpus.
        // Each export follows the query-then-fill convention, so every record is offered twice:
        // once with a NULL destination to learn the size the callee itself promises, then once
        // with a block of exactly that size (plus small deltas), pre-filled with a 0xCC sentinel.
        // Anything that changes at or past the promised size is a write beyond the callee's own
        // declaration, which is a stricter reading than the page guard the armed heap also gives.
        g_soft = 1;
        AddVectoredExceptionHandler(1, VehReport);
        HMODULE hm2 = LoadLibraryExA("OUTLMIME.dll", nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!hm2)
            hm2 = LoadLibraryExA("C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLMIME.dll",
                                 nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        printf("OUTLMIME=%p\n", (void *)hm2); fflush(stdout);
        if (!hm2) { printf("NOMOD\n"); return 12; }
        static const char *kinds[] = { "EssContentHint", "EssReceiptRequest", "EssReceipt",
                                       "EssMLHistory", "EssSecurityLabel", "EssKeyExchPreference",
                                       "EssSignCertificate" };
        const int NK = (int)(sizeof(kinds) / sizeof(kinds[0]));
        PFN_DASEX pDec[8];
        for (int k = 0; k < NK; k++) {
            char nm[80];
            _snprintf(nm, sizeof(nm) - 1, "%sDecodeEx", kinds[k]);
            pDec[k] = (PFN_DASEX)GetProcAddress(hm2, nm);
            printf("KIND %d %s dec=%p\n", k, kinds[k], (void *)pDec[k]);
        }
        fflush(stdout);
        size_t fsz = 0; BYTE *fb = LoadBlob(argv[1], &fsz);
        if (!fb) { printf("NOINPUT\n"); return 11; }
        // convention probe: the same tiny record offered to each kind under three call shapes, so a
        // callee-side fault can be told apart from a wrong argument convention on the first record.
        static const BYTE kGood[] = { 0x30,0x0B,0x06,0x09,0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x2E,0x01 };
        if (getenv("CRTF_PROBE")) {
            for (int k = 0; k < NK; k++) {
                if (!pDec[k]) continue;
                unsigned long nd; void *pv; int r;
                nd = 0; r = 0;
                __try { r = pDec[k](k, 0, (unsigned char *)kGood, sizeof(kGood), 0, nullptr, nullptr, &nd); }
                __except (EXCEPTION_EXECUTE_HANDLER) { r = -1; }
                printf("PROBE k=%d shapeA(flags0,pv=NULL) rc=%d need=%lu\n", k, r, nd);
                nd = 0; r = 0;
                __try { r = pDec[k](k, 0, (unsigned char *)kGood, sizeof(kGood), 0x8000, nullptr, nullptr, &nd); }
                __except (EXCEPTION_EXECUTE_HANDLER) { r = -1; }
                printf("PROBE k=%d shapeB(flags8000) rc=%d need=%lu\n", k, r, nd);
                nd = 0; pv = nullptr; r = 0;
                __try { r = pDec[k](k, 0, (unsigned char *)kGood, sizeof(kGood), 0x8000, nullptr, &pv, &nd); }
                __except (EXCEPTION_EXECUTE_HANDLER) { r = -1; }
                printf("PROBE k=%d shapeC(pvOut=&pv) rc=%d need=%lu pv=%p\n", k, r, nd, pv);
                fflush(stdout);
            }
            printf("PROBEEND\n"); fflush(stdout);
            return 0;
        }
        unsigned long recs = 0, entered = 0, fills = 0, pastn = 0, faults = 0;
        unsigned long percnt[8] = { 0 }, perenter[8] = { 0 }, perfault[8] = { 0 }, perpast[8] = { 0 };
        unsigned long maxpast = 0;
        static const unsigned long dl[3] = { 0, 1, 64 };
        size_t off = 0;
        unsigned long nmax = getenv("CRTF_NMAX") ? strtoul(getenv("CRTF_NMAX"), nullptr, 10) : 200000;
        while (off + 1 < fsz && recs < nmax) {
            size_t e1 = off; while (e1 < fsz && fb[e1] != '\n') e1++;
            if (e1 >= fsz) break;
            long want = strtol((char *)fb + off, nullptr, 10);
            size_t body = e1 + 1;
            if (want <= 0 || body + (size_t)want > fsz) break;
            off = body + want;
            if (off < fsz && fb[off] == '\n') off++;
            recs++;
            for (int k = 0; k < NK; k++) {
                if (!pDec[k]) continue;
                unsigned long need = 0;
                int q = 0;
                __try {
                    q = pDec[k](k, 0, fb + body, (ULONG)want, 0, nullptr, nullptr, &need);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    printf("FAULTQ r=%lu k=%d len=%ld code=%08x\n", recs, k, want,
                           (unsigned)GetExceptionCode()); fflush(stdout);
                    faults++; perfault[k]++; continue;
                }
                if (!q || !need || need > (64u << 20)) continue;
                entered++; perenter[k]++;
                for (int di = 0; di < 3; di++) {
                    unsigned long cap = need + dl[di];
                    unsigned char *o = (unsigned char *)malloc(cap + 512);
                    if (!o) continue;
                    memset(o, 0xCC, cap + 512);
                    unsigned long cb = cap;
                    int r = 0;
                    __try {
                        r = pDec[k](k, 0, fb + body, (ULONG)want, 0, nullptr, o, &cb);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        printf("FAULTR r=%lu k=%d len=%ld need=%lu d=%lu code=%08x\n", recs, k, want,
                               need, dl[di], (unsigned)GetExceptionCode()); fflush(stdout);
                        faults++; perfault[k]++; free(o); continue;
                    }
                    fills++;
                    unsigned long past = 0;
                    for (unsigned long z = need; z < cap + 512; z++)
                        if (o[z] != 0xCC) { past = cap + 512 - z; break; }
                    if (past) { pastn++; perpast[k]++; if (past > maxpast) maxpast = past; }
                    printf("D r=%lu k=%d len=%ld need=%lu d=%lu rc=%d cb=%lu past=%lu\n",
                           recs, k, want, need, dl[di], r, cb, past); fflush(stdout);
                    free(o);
                }
            }
        }
        for (int k = 0; k < NK; k++)
            printf("PERKIND %d %s recs=%lu entered=%lu faults=%lu past=%lu\n", k, kinds[k],
                   percnt[k], perenter[k], perfault[k], perpast[k]);
        printf("ESS42 recs=%lu entered=%lu fills=%lu past=%lu faults=%lu maxpast=%lu\n",
               recs, entered, fills, pastn, faults, maxpast);
        fflush(stdout);
        return 0;
    }
    if (mode == 59) {
        // Identify the ITnef vtable exactly, without trusting a build-to-build slot order:
        // HrGetOpenTnefStream(LPITNEF*) is a factory whose body is `*a1 = operator new(16); (**a1) =
        // &ImplOpenTnefStream::vftable`, so the object it hands out carries the live vtable. Print each
        // slot's RVA plus its first bytes so they can be matched against the 20144 build's named dump.
        typedef HRESULT(STDMETHODCALLTYPE *PFN_HGOTS)(void **);
        PFN_HGOTS pG = (PFN_HGOTS)GetProcAddress(g_hOlm, "HrGetOpenTnefStream");
        if (!pG) { printf("NOHGOTS\n"); return 7; }
        void *obj = nullptr;
        HRESULT hg = pG(&obj);
        printf("T9GOTS hr=%08x obj=%p\n", (unsigned)hg, obj); fflush(stdout);
        if (!obj || FAILED(hg)) return 8;
        void **vt = *(void ***)obj;
        uintptr_t base = (uintptr_t)g_hOlm;
        for (int k = 0; k < 16; k++) {
            unsigned char *f = (unsigned char *)vt[k];
            printf("T9SLOT %2d rva=0t%llX bytes=", k, (unsigned long long)((uintptr_t)f - base));
            for (int j = 0; j < 16; j++) printf("%02X", f[j]);
            printf("\n");
        }
        fflush(stdout);
        return 0;
    }
    if (mode == 58) {
        // The deep ITnef stages. OpenTnefStreamEx returns an LPITNEF whose first qword is the class
        // vtable (named in the 20144 build's .rdata: slot4 TNEF_ExtractProps, slot5 TNEF_Finish,
        // slot6 TNEF_OpenTaggedBody), and the free-function spellings of those are not exported, so the
        // slots are the only way in. This is the part of the decoder that hands out the tagged body
        // streams and materialises properties - the paths that "gotstream=0 / ex=0 / fin=0" never ran.
        g_soft = 1;
        PFN_OPEN_TNEF8 pOp8 = (PFN_OPEN_TNEF8)GetProcAddress(g_hOlm, "OpenTnefStreamEx");
        if (!pOp8) { printf("NOOPEN\n"); return 7; }
        typedef HRESULT(STDMETHODCALLTYPE *PFN_BODY)(void *, void *, ULONG, IStream **);
        typedef HRESULT(STDMETHODCALLTYPE *PFN_EXTR)(void *, ULONG, void *, void **);
        typedef HRESULT(STDMETHODCALLTYPE *PFN_FIN)(void *, ULONG, WORD *, void **);
        const ULONG tags[] = { 6u, 19u, 16u, 18u, 17u, 2000u, 14u, 13u, 12u, 11u, 10u, 9u, 8u, 7u, 5u, 4u, 3u, 2u, 1u, 22u };
        // one SPropTagArray with a spread of MAPI property ids, plus the TNEF attribute tags themselves
        ULONG propIds[64]; ULONG np = 0;
        for (ULONG t = 0; t < 32; t++) propIds[np++] = 0x0C000000u | (t * 0x1000u) | 30u;   // PT_UNICODE props
        for (ULONG t = 0; t < 16; t++) propIds[np++] = 0x30000000u | (t * 0x10u) | 258u;      // PR_BINARY-ish
        size_t fsz8 = 0; BYTE *fb8 = LoadBlob(argv[1], &fsz8);
        if (!fb8) { printf("NOINPUT\n"); return 11; }
        void *pMsg8 = nullptr, *pSess8 = nullptr, *pStg8 = nullptr; IMalloc *pMl8 = nullptr;
        PFN_OPENMSGSESS pS8 = (PFN_OPENMSGSESS)GetProcAddress(g_hOlm, "OpenIMsgSession");
        PFN_OPENMSGONI pO8 = (PFN_OPENMSGONI)GetProcAddress(g_hOlm, "OpenIMsgOnIStg");
        PFN_ALLOCBUF pA8 = (PFN_ALLOCBUF)GetProcAddress(g_hOlm, "MAPIAllocateBuffer");
        PFN_ALLOCMORE pAM8 = (PFN_ALLOCMORE)GetProcAddress(g_hOlm, "MAPIAllocateMore");
        PFN_FREEBUF pFB8 = (PFN_FREEBUF)GetProcAddress(g_hOlm, "MAPIFreeBuffer");
        const char *bm8 = getenv("CRTF_BASEMSG");
        if (bm8 && pS8 && pO8) {
            CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
            CoGetMalloc(MEMCTX_TASK, (IMalloc **)&pMl8);
            WCHAR wb8[1100]; MultiByteToWideChar(CP_ACP, 0, bm8, -1, wb8, 1090);
            StgOpenStorageEx(wb8, STGM_READWRITE | STGM_SHARE_EXCLUSIVE, STGFMT_STORAGE, 0,
                             nullptr, nullptr, __uuidof(IStorage), (void **)&pStg8);
            pS8((void *)pMl8, 0, &pSess8);
            pO8(pSess8, (void *)pA8, (void *)pAM8, (void *)pFB8, pMl8, nullptr, pStg8,
                nullptr, 0, 0, &pMsg8);
            printf("T8BASE msg=%p stg=%p\n", pMsg8, pStg8); fflush(stdout);
        }
        if (!pMsg8) { printf("T8NO_MSG (set CRTF_BASEMSG)\n"); return 12; }
        size_t off8 = 0; unsigned long n8 = 0, okc8 = 0, bodyok8 = 0, bodybytes8 = 0, extrc8 = 0, finok8 = 0;
        unsigned long extrcErr[8] = { 0 }, bodyErr[8] = { 0 };
        char *rec8 = (char *)malloc(64u << 20);
        ULONG fl8 = (argc > 2) ? (ULONG)strtoul(argv[2], nullptr, 16) : 2u;
        unsigned long nmax8 = getenv("CRTF_NMAX") ? strtoul(getenv("CRTF_NMAX"), nullptr, 10) : 200000;
        while (off8 + 1 < fsz8 && n8 < nmax8) {
            size_t e8 = off8; while (e8 < fsz8 && fb8[e8] != '\n') e8++;
            if (e8 >= fsz8) break;
            long want8 = strtol((char *)fb8 + off8, nullptr, 10);
            size_t body8 = e8 + 1;
            if (want8 < 0 || body8 + (size_t)want8 > fsz8 || (size_t)want8 > (64u << 20)) break;
            memcpy(rec8, (char *)fb8 + body8, want8);
            off8 = body8 + want8;
            if (off8 < fsz8 && fb8[off8] == '\n') off8++;
            IStream *ps8 = nullptr;
            if (FAILED(CreateStreamOnHGlobal(nullptr, TRUE, &ps8)) || !ps8) { n8++; continue; }
            ULONG put8 = 0;
            ps8->Write(rec8, (ULONG)want8, &put8);
            LARGE_INTEGER z8; z8.QuadPart = 0; ps8->Seek(z8, STREAM_SEEK_SET, nullptr);
            void *hT8 = nullptr;
            HRESULT h8 = pOp8(nullptr, ps8, (char *)"winmail.dat", fl8, pMsg8, 0x1234, nullptr, &hT8);
            if (SUCCEEDED(h8) && hT8) {
                okc8++;
                void **vt8 = *(void ***)hT8;
                PFN_BODY pBody8 = (PFN_BODY)vt8[6];
                PFN_EXTR pExtr8 = (PFN_EXTR)vt8[4];
                PFN_FIN pFin8 = (PFN_FIN)vt8[5];
                BYTE *db8 = (BYTE *)malloc(1u << 16);
                for (unsigned q = 0; q < sizeof(tags) / sizeof(tags[0]); q++) {
                    IStream *pb8 = nullptr;
                    HRESULT hb = pBody8(hT8, pMsg8, tags[q], &pb8);
                    if (SUCCEEDED(hb) && pb8) {
                        bodyok8++;
                        ULONG gg = 0, k = 0;
                        while (k < 400 && SUCCEEDED(pb8->Read(db8, 1u << 16, &gg)) && gg) { bodybytes8 += gg; k++; }
                        ((PFN_RELEASE)*(void **)*((void ***)pb8))(pb8);
                    } else {
                        int slot = (int)(hb == 0x80070057 ? 0 : hb == 0x80004005 ? 1 : hb == 0x8004010a ? 2 :
                                         hb == 0x80070002 ? 3 : hb == 0x8007000e ? 4 : hb == 0x00000001 ? 5 : 6);
                        bodyErr[slot]++;
                    }
                }
                free(db8);
                // SPropTagArray: cValues then the ids
                ULONG ta8[1 + 64];
                ta8[0] = np;
                for (ULONG i8 = 0; i8 < np; i8++) ta8[1 + i8] = propIds[i8];
                void *probs8 = nullptr;
                HRESULT he8 = pExtr8(hT8, np, ta8, &probs8);
                if (SUCCEEDED(he8)) extrc8++;
                int slot2 = (int)(he8 == 0x80070057 ? 0 : he8 == 0x80004005 ? 1 : he8 == 0x8004010a ? 2 :
                                  he8 == 0x80070002 ? 3 : he8 == 0x8007000e ? 4 : he8 == 0x00000001 ? 5 : 6);
                extrcErr[slot2]++;
                if (probs8 && pFB8) pFB8(probs8);
                WORD kv8 = 0; void *pf8 = nullptr;
                HRESULT hf8 = pFin8(hT8, 0, &kv8, &pf8);
                if (SUCCEEDED(hf8)) finok8++;
                if (pf8 && pFB8) pFB8(pf8);
            }
            ((PFN_RELEASE)*(void **)*((void ***)ps8))(ps8);
            n8++;
            if ((n8 % 50) == 0) {
                printf("T8PROG %lu ok=%lu body_ok=%lu body_bytes=%lu extr_ok=%lu fin_ok=%lu faults=%lu\n",
                       n8, okc8, bodyok8, bodybytes8, extrc8, finok8, g_faults); fflush(stdout);
            }
        }
        printf("T8CASES n=%lu ok=%lu body_ok=%lu body_bytes=%lu extr_ok=%lu fin_ok=%lu faults=%lu\n",
               n8, okc8, bodyok8, bodybytes8, extrc8, finok8, g_faults);
        printf("T8BODYERR 0=%lu 1=%lu 2=%lu 3=%lu 4=%lu 5=%lu 6=%lu\n",
               bodyErr[0], bodyErr[1], bodyErr[2], bodyErr[3], bodyErr[4], bodyErr[5], bodyErr[6]);
        printf("T8EXTRERR 0=%lu 1=%lu 2=%lu 3=%lu 4=%lu 5=%lu 6=%lu\n",
               extrcErr[0], extrcErr[1], extrcErr[2], extrcErr[3], extrcErr[4], extrcErr[5], extrcErr[6]);
        fflush(stdout);
        return 0;
    }
    if (mode == 56) {
        // Drive the shell IFilter that Windows resolves for a file extension, inside this process.
        // HKCR\<ext>\shellex\{89785937-...} names the object, and that same GUID is IID_IFilter, so the
        // registry lookup plus one CoCreateInstance reaches Office's own document reader (wwlib through
        // the Word filter, Excel through its own) without any UI - which is also the indexer's path.
        // Text bytes extracted per file is the coverage gate: a file that yields no text never reached
        // the body parser, so "no fault" on it would mean nothing.
        const char *list = getenv("CRTF_LIST");
        char *lb = nullptr; size_t lsz = 0;
        if (list) {
            HANDLE hl = CreateFileA(list, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
            if (hl == INVALID_HANDLE_VALUE) { printf("NOLIST\n"); return 11; }
            DWORD sz = GetFileSize(hl, nullptr);
            lb = (char *)malloc(sz + 1); DWORD rd = 0;
            ReadFile(hl, lb, sz, &rd, nullptr); lb[rd] = 0; lsz = rd; CloseHandle(hl);
        } else {
            printf("NOLIST (set CRTF_LIST to a file of paths)\n"); return 2;
        }
        CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        static const IID iidIF = { 0x89785937, 0x9A15, 0x475B,
            { 0x82, 0x5F, 0x30, 0xD1, 0xFA, 0xBA, 0xE6, 0xD1 } };
        typedef HRESULT (STDMETHODCALLTYPE *PFN_IF_INIT)(void *, ULONG);
        typedef HRESULT (STDMETHODCALLTYPE *PFN_IF_RESET)(void *);
        typedef HRESULT (STDMETHODCALLTYPE *PFN_IF_GTC)(void *, LPWSTR *);
        typedef HRESULT (STDMETHODCALLTYPE *PFN_IF_REL)(void *);
        unsigned long nf = 0, nok = 0, ntext = 0, nzero = 0, maxb = 0;
        char *nl = lb;
        while (nl && *nl) {
            char *eol = strchr(nl, '\n'); if (eol) *eol = 0;
            char *path = nl; while (*path == ' ' || *path == '\r') path++;
            nl = eol ? eol + 1 : nullptr;
            if (!*path) continue;
            const char *dot = strrchr(path, '.');
            if (!dot) continue;
            nf++;
            char key[420];
            _snprintf(key, sizeof(key) - 1, "%s\\shellex\\{89785937-9A15-475B-825F-30D1FABAE6D1}", dot);
            key[sizeof(key) - 1] = 0;
            WCHAR wkey[420], wcls[80]; LONG cb = 80 * 2;
            MultiByteToWideChar(CP_ACP, 0, key, -1, wkey, 420);
            HKEY hk = nullptr;
            if (RegOpenKeyExW(HKEY_CLASSES_ROOT, wkey, 0, KEY_READ | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS) {
                printf("IFH NOSUCH %s\n", path); continue;
            }
            wcls[0] = 0;
            if (RegQueryValueW(hk, nullptr, wcls, &cb) != ERROR_SUCCESS) { RegCloseKey(hk); printf("IFH NOCLS %s\n", path); continue; }
            RegCloseKey(hk);
            CLSID cid;
            if (FAILED(CLSIDFromString(wcls, &cid))) { printf("IFH BADCLS %s\n", path); continue; }
            void *obj = nullptr;
            HRESULT hc = CoCreateInstance(cid, nullptr, CLSCTX_INPROC_SERVER | CLSCTX_INPROC_HANDLER, iidIF, &obj);
            if (FAILED(hc) || !obj) { printf("IFH CCI=%08x %s\n", (unsigned)hc, path); continue; }
            void **vt = *(void ***)obj;
            PFN_IF_INIT pInit = (PFN_IF_INIT)vt[3];
            PFN_IF_RESET pReset = (PFN_IF_RESET)vt[5];
            PFN_IF_GTC pGtc = (PFN_IF_GTC)vt[9];
            PFN_IF_REL pRel = (PFN_IF_REL)vt[2];
            HRESULT hi = pInit(obj, 0);
            unsigned long chunks = 0, bytes = 0;
            if (SUCCEEDED(hi)) {
                for (;;) {
                    LPWSTR pwz = nullptr;
                    HRESULT ht = pGtc(obj, &pwz);
                    if (ht != S_OK) { if (pwz) CoTaskMemFree(pwz); break; }
                    if (pwz) { bytes += (unsigned long)(wcslen(pwz) * 2); CoTaskMemFree(pwz); }
                    if (++chunks > 40000) break;
                }
                pReset(obj);
            }
            pRel(obj);
            nok++;
            if (bytes) ntext++; else nzero++;
            if (bytes > maxb) maxb = bytes;
            char clsA[80]; wcopy(clsA, sizeof(clsA), wcls);
            printf("IFH init=%08x chunks=%lu bytes=%lu cls=%s %s\n", (unsigned)hi, chunks, bytes, clsA, path);
            fflush(stdout);
        }
        printf("IFSUM files=%lu created=%lu with_text=%lu zero_text=%lu maxbytes=%lu\n",
               nf, nok, ntext, nzero, (unsigned long)maxb); fflush(stdout);
        return 0;
    }
    if (mode == 55) {
        // List every export of the loaded module whose name matches CRTF_MATCH (default "tnef").
        // The TNEF C API (TNEFExtractProps/TNEFFinish/...) is reached through the mapistub forwarders,
        // so whether OLMAPI32 itself carries the name, carries it under another spelling, or exports
        // it by ordinal only decides how the deep extraction path can be entered in-process.
        HMODULE hm = GetModuleHandleA(getenv("CRTF_MOD") ? getenv("CRTF_MOD") : "OLMAPI32.dll");
        if (!hm && getenv("CRTF_MOD"))
            hm = LoadLibraryExA(getenv("CRTF_MOD"), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!hm) { printf("NOMOD\n"); return 12; }
        IMAGE_DOS_HEADER *dd55 = (IMAGE_DOS_HEADER *)hm;
        IMAGE_NT_HEADERS64 *nn55 = (IMAGE_NT_HEADERS64 *)((char *)hm + dd55->e_lfanew);
        IMAGE_DATA_DIRECTORY *edx = &nn55->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!edx->Size) { printf("NOEXPORTDIR\n"); return 0; }
        IMAGE_EXPORT_DIRECTORY *ex = (IMAGE_EXPORT_DIRECTORY *)((char *)hm + edx->VirtualAddress);
        unsigned int *funcs = (unsigned int *)((char *)hm + ex->AddressOfFunctions);
        unsigned int *nms = (unsigned int *)((char *)hm + ex->AddressOfNames);
        unsigned short *ords = (unsigned short *)((char *)hm + ex->AddressOfNameOrdinals);
        const char *mt = getenv("CRTF_MATCH") ? getenv("CRTF_MATCH") : "tnef";
        printf("EXP total=%u names=%u match=%s\n", ex->NumberOfFunctions, ex->NumberOfNames, mt);
        int hit = 0;
        for (unsigned i = 0; i < ex->NumberOfNames; i++) {
            const char *nm = (const char *)hm + nms[i];
            char low[256]; int k = 0;
            for (; nm[k] && k < 255; k++) low[k] = (char)tolower((unsigned char)nm[k]);
            low[k] = 0;
            if (!strstr(low, mt)) continue;
            hit++;
            printf("  [%u] ord=%u rva=0x%X %s\n", i, ords[i] + ex->Base, funcs[ords[i]], nm);
        }
        printf("EXP hits=%d\n", hit); fflush(stdout);
        return 0;
    }
    if (mode == 54) {
        // Control for the tail-guard allocator: the last in-bounds byte must be writable, the first
        // byte past the end must fault, and the fault must be reported at guard-page address
        // (user + n). Run it with CRTF_GUARD=1 through mode 52 so the slots really are replaced.
        volatile char *g54;
        {
            char *p = (char *)malloc(0x100);
            char *q = (char *)malloc(0x10000);
            printf("GCTRL p=%p q=%p p_end=%p q_end=%p\n", p, q, p + 0x100, q + 0x10000); fflush(stdout);
            p[0xFF] = 0x41; q[0xFFFF] = 0x42;
            printf("GCTRL inbounds_ok p[0xFF]=%02x q[0xFFFF]=%02x\n",
                   (unsigned char)p[0xFF], (unsigned char)q[0xFFFF]); fflush(stdout);
            p = (char *)realloc(p, 0x400);
            printf("GCTRL after_realloc p=%p p[0xFF]=%02x\n", p, (unsigned char)p[0xFF]); fflush(stdout);
            p[0x400] = 0x43;                          // must fault: one byte past the new end
            printf("GCTRL NOT_DETECTED\n"); fflush(stdout);
            free(q); g54 = p; (void)g54;
        }
        return 0;
    }
    if (mode == 51) {
        // Calibration for the release classifier, three shapes in one run:
        //   C1 one block released twice            -> the observer must call this DUPFREE
        //   C2 release, then the same address handed out again and released once
        //                                          -> must NOT be called DUPFREE (recycling)
        //   C3 block obtained from the allocator without going through the observed slot, released
        //      through it                            -> must be called UNTRACKED, not DUPFREE
        // A run whose C1 does not appear says the observer is blind, not that the target is clean.
        typedef void *(STDAPICALLTYPE *PFN_RAW_MALLOC)(size_t);
        PFN_RAW_MALLOC rawMalloc = (PFN_RAW_MALLOC)(void *)GetProcAddress(
            GetModuleHandleA("ucrtbase.dll"), "malloc");
        void *b = malloc(0x4321);
        printf("CTRL b=%p rawmalloc=%p\n", b, (void *)rawMalloc); fflush(stdout);
        free(b);                             // single release of a second block: must stay silent
        {
            void *c1 = malloc(0x2222);
            free(c1);
            void *c2 = malloc(0x2222);       // C2 - normally the very address just released
            printf("CTRL_RECYCLE c1=%p c2=%p same=%d\n", c1, c2, c1 == c2); fflush(stdout);
            free(c2);
        }
        if (rawMalloc) {
            void *d = rawMalloc(0x333);       // C3 - allocated outside the observed slot
            printf("CTRL_UNTRACKED d=%p\n", d); fflush(stdout);
            free(d);
        }
        printf("CTRL mid\n"); fflush(stdout);
        void *a = malloc(0x1234);
        printf("CTRL a=%p\n", a); fflush(stdout);
        free(a);
        free(a);                             // C1 last: the CRT itself can abort on this one
        printf("CTRL done\n"); fflush(stdout);
        Sleep(200);
        return 0;
    }
    if (mode == 50) {
        // Both sides of OLMAPI32's allocator view, plus the descriptor probe. The malloc log is the
        // discriminator: if the descriptor converter ran at all, its MapiMessageW / MapiFileDescW /
        // per-string allocations appear with their sizes and call sites; if MAPISendMail bailed at
        // one of its argument checks first, nothing of that shape appears.
        g_soft = 0;
        HMODULE ho = GetModuleHandleA("OLMAPI32.dll");
        if (!ho) ho = LoadLibraryExA("OLMAPI32.dll", nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!ho) { printf("NOMOD\n"); return 12; }
        IMAGE_DOS_HEADER *dh6 = (IMAGE_DOS_HEADER *)ho;
        IMAGE_NT_HEADERS64 *nt6 = (IMAGE_NT_HEADERS64 *)((char *)ho + dh6->e_lfanew);
        IMAGE_DATA_DIRECTORY *dd6 = &nt6->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        void **sfree = nullptr, **smallo = nullptr;
        for (IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)((char *)ho + dd6->VirtualAddress);
             imp && imp->Name; imp++) {
            const char *dn = (const char *)ho + imp->Name;
            if (_stricmp(dn, "api-ms-win-crt-heap-l1-1-0.dll") && _stricmp(dn, "ucrtbase.dll")
                && _stricmp(dn, "msvcrt.dll")) continue;
            if (!imp->FirstThunk || !imp->OriginalFirstThunk) continue;
            IMAGE_THUNK_DATA64 *ft = (IMAGE_THUNK_DATA64 *)((char *)ho + imp->FirstThunk);
            IMAGE_THUNK_DATA64 *it = (IMAGE_THUNK_DATA64 *)((char *)ho + imp->OriginalFirstThunk);
            for (unsigned j = 0; it[j].u1.AddressOfData; j++) {
                if (it[j].u1.Ordinal & IMAGE_ORDINAL_FLAG64) continue;
                IMAGE_IMPORT_BY_NAME *ib = (IMAGE_IMPORT_BY_NAME *)((char *)ho + it[j].u1.AddressOfData);
                const char *nm = (const char *)ib->Name;
                if (strcmp(nm, "free") == 0) sfree = (void **)&ft[j].u1.AddressOfData;
                if (strcmp(nm, "malloc") == 0) smallo = (void **)&ft[j].u1.AddressOfData;
            }
        }
        g_dfmod = (unsigned char *)ho;
        printf("slot free=%p malloc=%p\n", (void *)sfree, (void *)smallo); fflush(stdout);
        if (!sfree || !smallo) { printf("NOSLOT\n"); return 13; }
        DWORD op = 0;
        VirtualProtect(sfree, 8, PAGE_READWRITE, &op);
        g_dfreal = (PFN_FREE_T)*sfree; *sfree = (void *)&HookFree;
        VirtualProtect(sfree, 8, op, &op);
        VirtualProtect(smallo, 8, PAGE_READWRITE, &op);
        g_dmreal = (PFN_MALLOC_T)*smallo; *smallo = (void *)&HookMalloc;
        VirtualProtect(smallo, 8, op, &op);
        typedef unsigned long (STDAPICALLTYPE *PFN_SEND50)(void *, unsigned long long, void *, unsigned long, unsigned long);
        PFN_SEND50 pS = (PFN_SEND50)GetProcAddress(ho, "MAPISendMail");
        if (!pS) { printf("NOSEND\n"); return 15; }
        size_t mb = getenv("CRTF_MB") ? (size_t)strtoul(getenv("CRTF_MB"), nullptr, 10) : 0;
        char *big = nullptr;
        if (mb) {
            big = (char *)VirtualAlloc(nullptr, mb + 16, MEM_COMMIT, PAGE_READWRITE);
            if (big) { memset(big, 'A', mb); big[mb] = 0; }
            printf("BIG %zu MB -> %p\n", mb, (void *)big); fflush(stdout);
        }
        static unsigned char msg[96], fd[40];
        memset(msg, 0, sizeof(msg)); memset(fd, 0, sizeof(fd));
        int cs = getenv("CRTF_CASE") ? atoi(getenv("CRTF_CASE")) : 1;
        unsigned long ulr = getenv("CRTF_ULRESV") ? strtoul(getenv("CRTF_ULRESV"), nullptr, 10) : 65001;
        unsigned long fl = getenv("CRTF_FLAGS") ? strtoul(getenv("CRTF_FLAGS"), nullptr, 16) : 0xC;
        static char badn[] = "\xED\xA0\x80", goodn[] = "note.txt", goodp[] = "C:\\a.txt";
        *(unsigned long *)(msg + 0x00) = ulr;
        *(unsigned long *)(msg + 0x50) = 1;
        *(void **)(msg + 0x58) = fd;
        *(char **)(fd + 0x10) = goodp;
        if (cs == 1) *(char **)(fd + 0x18) = badn;
        else if (cs == 2 && big) { *(char **)(fd + 0x18) = big; }
        else *(char **)(fd + 0x18) = goodn;
        unsigned long hr = 0;
        __try { hr = pS(nullptr, 0, msg, fl, 0); }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            printf("EXC code=%08x\n", (unsigned)GetExceptionCode()); fflush(stdout); return 20;
        }
        printf("CS %d ulr=%lu flags=%lX hr=%08x mallocs=%d releases=%d doubles=%d\n",
               cs, ulr, fl, (unsigned)hr, g_amn, g_dfall, g_dfdbl); fflush(stdout);
        for (int i = 0; i < g_amn && i < 40; i++)
            printf("  ALLOC#%d size=%llu ptr=%p from=olmapi32+0t%llX\n", i, (unsigned long long)g_asz[i],
                   g_am[i], (unsigned long long)(g_art[i] - (unsigned char *)ho));
        fflush(stdout);
        return 0;
    }
    if (mode == 49) {
        // Same hook as mode 48, but the failing condition is chosen so that it can be produced
        // deterministically: HrConvertStringToWideChar computes cch from the string itself and then
        // mallocs 2*cch, so an oversized descriptor string is the one input that makes that
        // allocation (or the width conversion's own sizing) fail, which is what drives execution
        // onto the cleanup pad that releases the descriptor array twice.
        g_soft = 0;
        HMODULE ho = GetModuleHandleA("OLMAPI32.dll");
        if (!ho) ho = LoadLibraryExA("OLMAPI32.dll", nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!ho) { printf("NOMOD\n"); return 12; }
        IMAGE_DOS_HEADER *dh5 = (IMAGE_DOS_HEADER *)ho;
        IMAGE_NT_HEADERS64 *nt5 = (IMAGE_NT_HEADERS64 *)((char *)ho + dh5->e_lfanew);
        IMAGE_DATA_DIRECTORY *dd5 = &nt5->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        void **slot = nullptr;
        for (IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)((char *)ho + dd5->VirtualAddress);
             imp && imp->Name; imp++) {
            const char *dn = (const char *)ho + imp->Name;
            if (_stricmp(dn, "api-ms-win-crt-heap-l1-1-0.dll") && _stricmp(dn, "ucrtbase.dll")
                && _stricmp(dn, "msvcrt.dll")) continue;
            if (!imp->FirstThunk || !imp->OriginalFirstThunk) continue;
            IMAGE_THUNK_DATA64 *ft = (IMAGE_THUNK_DATA64 *)((char *)ho + imp->FirstThunk);
            IMAGE_THUNK_DATA64 *it = (IMAGE_THUNK_DATA64 *)((char *)ho + imp->OriginalFirstThunk);
            for (unsigned j = 0; it[j].u1.AddressOfData; j++) {
                if (it[j].u1.Ordinal & IMAGE_ORDINAL_FLAG64) continue;
                IMAGE_IMPORT_BY_NAME *ib = (IMAGE_IMPORT_BY_NAME *)((char *)ho + it[j].u1.AddressOfData);
                if (strcmp((const char *)ib->Name, "free") == 0) slot = (void **)&ft[j].u1.AddressOfData;
            }
        }
        g_dfmod = (unsigned char *)ho;
        if (!slot) { printf("NOSLOT\n"); return 13; }
        DWORD oldp = 0;
        VirtualProtect(slot, 8, PAGE_READWRITE, &oldp);
        g_dfreal = (PFN_FREE_T)*slot;
        *slot = (void *)&HookFree;
        VirtualProtect(slot, 8, oldp, &oldp);
        printf("HOOK ok releases_tracked_from=olmapi32\n"); fflush(stdout);
        typedef unsigned long (STDAPICALLTYPE *PFN_SEND49)(void *, unsigned long long, void *, unsigned long, unsigned long);
        PFN_SEND49 pS = (PFN_SEND49)GetProcAddress(ho, "MAPISendMail");
        if (!pS) { printf("NOSEND\n"); return 15; }
        size_t mb = getenv("CRTF_MB") ? (size_t)strtoul(getenv("CRTF_MB"), nullptr, 10) : 2048;
        char *big = (char *)VirtualAlloc(nullptr, mb + 16, MEM_COMMIT, PAGE_READWRITE);
        printf("BIG %zu MB at %p (%s)\n", mb, (void *)big, big ? "committed" : "VIRTUALALLOC_FAILED");
        fflush(stdout);
        if (!big) return 16;
        memset(big, 'A', mb); big[mb] = 0;
        static unsigned char msg[96], fd[40];
        memset(msg, 0, sizeof(msg)); memset(fd, 0, sizeof(fd));
        *(unsigned long *)(msg + 0x00) = 65001;                 // CP_UTF8 selection
        *(unsigned long *)(msg + 0x50) = 1;                     // nFileCount
        *(void **)(msg + 0x58) = fd;                            // lpFiles
        int cs = getenv("CRTF_CASE") ? atoi(getenv("CRTF_CASE")) : 1;
        if (cs == 1) *(char **)(fd + 0x18) = big;                // lpszFileName
        else *(char **)(fd + 0x10) = big;                       // lpszPathName
        unsigned long hr = 0;
        __try { hr = pS(nullptr, 0, msg, 0xC, 0); }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            printf("EXC code=%08x\n", (unsigned)GetExceptionCode()); fflush(stdout); return 20;
        }
        printf("MB=%zu CASE %d hr=%08x tracked=%d releases=%d doubles=%d\n",
               mb, cs, (unsigned)hr, g_dfen, g_dfall, g_dfdbl); fflush(stdout);
        return 0;
    }
    if (mode == 48) {
        g_soft = 0;
        HMODULE ho = GetModuleHandleA("OLMAPI32.dll");
        if (!ho) ho = LoadLibraryExA("OLMAPI32.dll", nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!ho) { printf("NOMOD\n"); return 12; }
        IMAGE_DOS_HEADER *dh4 = (IMAGE_DOS_HEADER *)ho;
        IMAGE_NT_HEADERS64 *nt4 = (IMAGE_NT_HEADERS64 *)((char *)ho + dh4->e_lfanew);
        IMAGE_DATA_DIRECTORY *dd4 = &nt4->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        void **slot = nullptr;
        if (dd4->Size) {
            for (IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)((char *)ho + dd4->VirtualAddress);
                 imp->Name; imp++) {
                const char *dn = (const char *)ho + imp->Name;
                if (_stricmp(dn, "api-ms-win-crt-heap-l1-1-0.dll") && _stricmp(dn, "ucrtbase.dll")
                    && _stricmp(dn, "msvcrt.dll")) continue;
                if (!imp->FirstThunk || !imp->OriginalFirstThunk) continue;
                IMAGE_THUNK_DATA64 *ft = (IMAGE_THUNK_DATA64 *)((char *)ho + imp->FirstThunk);
                IMAGE_THUNK_DATA64 *it = (IMAGE_THUNK_DATA64 *)((char *)ho + imp->OriginalFirstThunk);
                for (unsigned j = 0; it[j].u1.AddressOfData; j++) {
                    if (it[j].u1.Ordinal & IMAGE_ORDINAL_FLAG64) continue;
                    IMAGE_IMPORT_BY_NAME *ib = (IMAGE_IMPORT_BY_NAME *)((char *)ho + it[j].u1.AddressOfData);
                    if (strcmp((const char *)ib->Name, "free") == 0) slot = (void **)&ft[j].u1.AddressOfData;
                }
            }
        }
        g_dfmod = (unsigned char *)ho;
        printf("slot=%p rva=0x%llX\n", (void *)slot,
               slot ? (unsigned long long)((char *)slot - (char *)ho) : 0ull); fflush(stdout);
        if (!slot) { printf("NOSLOT\n"); return 13; }
        DWORD oldp = 0;
        if (!VirtualProtect(slot, sizeof(void *), PAGE_READWRITE, &oldp)) { printf("VPFAIL\n"); return 14; }
        g_dfreal = (PFN_FREE_T)*slot;
        *slot = (void *)&HookFree;
        VirtualProtect(slot, sizeof(void *), oldp, &oldp);
        printf("HOOK installed real=%p\n", (void *)g_dfreal); fflush(stdout);
        typedef unsigned long (STDAPICALLTYPE *PFN_SEND48)(void *, unsigned long long, void *, unsigned long, unsigned long);
        PFN_SEND48 pS = (PFN_SEND48)GetProcAddress(ho, "MAPISendMail");
        if (!pS) { printf("NOSEND\n"); return 15; }
        int cs = getenv("CRTF_CASE") ? atoi(getenv("CRTF_CASE")) : 1;
        static unsigned char msg[96], fd[64];
        memset(msg, 0, sizeof(msg)); memset(fd, 0, sizeof(fd));
        static char goodn[] = "note.txt", goodp[] = "C:\\tmp\\a.txt";
        static char badn[64];
        if (getenv("CRTF_BADHEX")) {
            const char *h = getenv("CRTF_BADHEX");
            int k = 0;
            while (h[0] && h[1] && k < 32) {
                unsigned v = 0;
                sscanf(h, "%2x", &v);
                badn[k++] = (char)v; h += 2;
            }
            badn[k] = 0;
            printf("BADHEX %d bytes\n", k); fflush(stdout);
        } else {
            strcpy(badn, "\xED\xA0\x80");
        }
        *(unsigned long *)(msg + 0x00) = 65001;
        *(unsigned long *)(msg + 0x50) = 1;
        *(void **)(msg + 0x58) = fd;
        if (cs == 1) *(char **)(fd + 0x18) = badn;              // the file name carries the bytes
        else if (cs == 4) *(char **)(fd + 0x10) = badn;         // the path carries them
        else if (cs == 5) { *(char **)(msg + 0x28) = badn;      // a message-level string
                             *(char **)(fd + 0x18) = goodn; }
        else { *(char **)(fd + 0x18) = goodn; *(char **)(fd + 0x10) = goodp; }  // control: succeeds
        unsigned long hr = 0;
        __try { hr = pS(nullptr, 0, msg, 0xC, 0); }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            printf("EXC code=%08x\n", (unsigned)GetExceptionCode()); fflush(stdout); return 20;
        }
        printf("CASE %d hr=%08x tracked_pointers=%d releases=%d doubles=%d\n",
               cs, (unsigned)hr, g_dfen, g_dfall, g_dfdbl); fflush(stdout);
        for (int i = 0; i < g_dfen; i++)
            if (g_df[i].n > 1)
                printf("DUP p=%p n=%d r1=olmapi32+0t%llX\n", g_df[i].p, g_df[i].n,
                       (unsigned long long)((char *)g_df[i].r1 - (char *)g_dfmod));
        fflush(stdout);
        return 0;
    }
    if (mode == 47) {
        // Binary-level scan for "release helper, then free the same register".
        // x64 form of the shape found in HrConvertFileDescToUnicode's failure pad:
        //     48 8B Dx            mov     rdx, rX        ; helper's 2nd arg = the block
        //     <0..6 bytes>        (the count argument set-up)
        //     E8 ....             call    helper         ; the helper frees the block itself
        //     48 8B Cx            mov     rcx, rX        ; SAME register, unmodified
        //     FF 15 ....          call    cs:__imp_free  ; second release of that block
        // Matching on bytes rather than decompiled text keeps working across builds and is not
        // affected by the calls the decompiler renders as MEMORY[0].
        const char *modname = argv[2] && argv[2][0] ? argv[2] : "OLMAPI32.dll";
        HMODULE hm = GetModuleHandleA(modname);
        if (!hm) hm = LoadLibraryExA(modname, nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        printf("module=%s hmod=%p\n", modname, (void *)hm); fflush(stdout);
        if (!hm) { printf("NOMOD\n"); return 12; }
        IMAGE_DOS_HEADER *dh = (IMAGE_DOS_HEADER *)hm;
        IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)((char *)hm + dh->e_lfanew);
        IMAGE_SECTION_HEADER *sh = IMAGE_FIRST_SECTION(nt);
        struct SECT { unsigned char *p; unsigned long sz; unsigned long rva; };
        static SECT secs[12]; int nsec = 0;
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections && nsec < 12; i++)
            if ((sh[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && !(sh[i].Characteristics & IMAGE_SCN_MEM_WRITE)) {
                secs[nsec].p = (unsigned char *)hm + sh[i].VirtualAddress;
                secs[nsec].sz = sh[i].Misc.VirtualSize;
                secs[nsec].rva = sh[i].VirtualAddress;
                printf("code[%d] rva=0x%lX size=0x%lX\n", nsec, sh[i].VirtualAddress, sh[i].Misc.VirtualSize);
                nsec++;
            }
        if (!nsec) { printf("NOCODE\n"); return 13; }
        unsigned char *code = nullptr; unsigned long codeSz = 0;   // set per section below
        // the IAT slot the second call must go through: resolve "free" from the import directory
        unsigned long long freeSlot = 0;
        IMAGE_DATA_DIRECTORY *dd = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (dd->Size) {
            for (IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)((char *)hm + dd->VirtualAddress);
                 imp->Name; imp++) {
                const char *dn = (const char *)hm + imp->Name;
                BOOL api = _stricmp(dn, "api-ms-win-crt-heap-l1-1-0.dll") == 0 ||
                           _stricmp(dn, "ucrtbase.dll") == 0 || _stricmp(dn, "msvcrt.dll") == 0 ||
                           _stricmp(dn, "VCRUNTIME140.dll") == 0;
                if (!api) continue;
                if (!imp->FirstThunk) continue;
                IMAGE_THUNK_DATA64 *ft = (IMAGE_THUNK_DATA64 *)((char *)hm + imp->FirstThunk);
                IMAGE_THUNK_DATA64 *it = imp->OriginalFirstThunk
                    ? (IMAGE_THUNK_DATA64 *)((char *)hm + imp->OriginalFirstThunk) : nullptr;
                for (unsigned j = 0; ft[j].u1.AddressOfData; j++) {
                    const char *nm = nullptr;
                    if (it && !(it[j].u1.Ordinal & IMAGE_ORDINAL_FLAG64))
                        nm = (const char *)hm + it[j].u1.AddressOfData + 2;
                    if (nm && strcmp(nm, "free") == 0) freeSlot = (unsigned long long)&ft[j].u1.AddressOfData;
                }
            }
        }
        printf("free_iat_slot=0x%llX (rva 0x%llX)\n", freeSlot, hm ? freeSlot - (unsigned long long)hm : 0);
        unsigned long hits = 0, scanned = 0;
        for (int si = 0; si < nsec; si++) {
        code = secs[si].p; codeSz = secs[si].sz;
        for (unsigned long o = 0; o + 16 <= codeSz; o++, scanned++) {
            if (code[o] != 0x48 || code[o + 1] != 0x8B || (code[o + 2] & 0xF0) != 0xD0) continue;
            int n = code[o + 2] & 0x0F;                       // rX passed as the helper's 2nd arg
            for (int k = 0; k <= 6; k++) {
                unsigned long p = o + 3 + k;
                if (p + 11 > codeSz) break;
                if (code[p] != 0xE8) continue;                 // call helper
                if (!(code[p + 5] == 0x48 && code[p + 6] == 0x8B && code[p + 7] == (0xC0 | n))) continue;
                if (code[p + 8] != 0xFF || code[p + 9] != 0x15) continue;
                long long rip = (long long)(code + p + 14);
                unsigned tgt = *(unsigned *)(code + p + 10);
                unsigned long long slot = (unsigned long long)(rip + (int)tgt);
                if (freeSlot && slot != freeSlot) continue;
                long long rel = (int)*(unsigned *)(code + p + 1);
                unsigned long helperRva = (unsigned long)((code + p + 5 + rel) - (unsigned char *)hm);
                hits++;
                printf("HIT rva=0x%lX helper_rva=0x%lX reg=r%s pad_at_rva=0x%lX bytes=%02X %02X %02X %02X %02X\n",
                       o + (unsigned long)((unsigned char *)code - (unsigned char *)hm), helperRva,
                       n == 3 ? "bx" : n == 4 ? "sp" : n == 5 ? "bp" : n == 6 ? "si" : n == 7 ? "di" :
                       n == 0 ? "rax" : n == 1 ? "rcx" : n == 2 ? "rdx" : "r8?",
                       o + 5 + (unsigned long)((unsigned char *)code - (unsigned char *)hm),
                       code[o], code[o + 1], code[o + 2], code[p], code[p + 7]);
                fflush(stdout);
                o = p + 7; break;
            }
        }
        }
        printf("PDFSCAN mod=%s scanned=%lu hits=%lu\n", modname, scanned, hits);
        fflush(stdout);
        return 0;
    }
    if (mode == 46) {
        // Block-reuse probe. OLMAPI32's descriptor converters release through the UCRT heap
        // (api-ms-win-crt-heap-l1-1-0 malloc/free), which is the same heap this /MD host
        // allocates from, and that allocator does not police a second free of a live chunk.
        // So the question is not "did it fault" but "can two owners end up holding one block":
        // leave a free chunk of the array's size, optionally run the call that is supposed to
        // free it twice, then take two allocations of that size and see whether they collide.
        // CRTF_CALL=0 is the control arm (no call), CRTF_CALL=1 the measured arm.
        g_soft = 0;
        HMODULE ho = GetModuleHandleA("OLMAPI32.dll");
        if (!ho) ho = LoadLibraryExA("OLMAPI32.dll", nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        typedef unsigned long (STDAPICALLTYPE *PFN_SENDMAIL)(void *, unsigned long long, void *,
                                                             unsigned long, unsigned long);
        PFN_SENDMAIL pSend = (PFN_SENDMAIL)GetProcAddress(ho, "MAPISendMail");
        if (!pSend) { printf("NOSEND\n"); return 12; }
        int cs = getenv("CRTF_CASE") ? atoi(getenv("CRTF_CASE")) : 1;
        int doCall = getenv("CRTF_CALL") ? atoi(getenv("CRTF_CALL")) : 1;
        static unsigned char msg[96];
        static unsigned char fdarea[160];
        memset(msg, 0, sizeof(msg)); memset(fdarea, 0, sizeof(fdarea));
        *(unsigned long *)(msg + 0x00) = 65001;              // CP_UTF8 selector
        *(unsigned long *)(msg + 0x50) = 1;                  // nFileCount
        *(void **)(msg + 0x58) = fdarea;                     // lpFiles
        static char badn[] = "\xED\xA0\x80";
        static char badp[] = "\xC0\x80";
        static char goodn[] = "note.txt";
        static char goodp[] = "C:\\tmp\\a.txt";
        if (cs == 1) { *(char **)(fdarea + 0x10) = badp; }
        else if (cs == 2) { *(char **)(fdarea + 0x18) = badn; }
        else if (cs == 3) { *(char **)(fdarea + 0x10) = badp; *(char **)(fdarea + 0x18) = badn; }
        else { *(char **)(fdarea + 0x10) = goodp; *(char **)(fdarea + 0x18) = goodn; }
        size_t sz = 40;                                      // one MapiFileDesc slot
        void *a = malloc(sz); void *b = malloc(sz);
        printf("PRE  case=%d call=%d a=%p b=%p same=%d\n", cs, doCall, a, b, a == b);
        free(a); free(b);
        a = malloc(sz); free(a);                             // leave a sz-byte chunk on the list
        if (doCall) {
            printf("CALL MAPISendMail case=%d\n", cs); fflush(stdout);
            __try {
                unsigned long hr = pSend(nullptr, 0, msg, 0xC, 0);
                printf("CALL returned hr=%08x\n", (unsigned)hr);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                printf("EXC code=%08x\n", (unsigned)GetExceptionCode());
            }
            fflush(stdout);
        }
        void *x = malloc(sz); void *y = malloc(sz);
        printf("POST x=%p y=%p same=%d\n", x, y, x == y);
        if (x && y && x == y) {
            memset(x, 0x41, sz);
            unsigned char *q = (unsigned char *)y;
            printf("ALIAS two owners of one block: x[0]=%02X y[0]=%02X same=%d\n",
                   (unsigned)((unsigned char *)x)[0], (unsigned)q[0], 1);
        }
        fflush(stdout);
        return 0;
    }
    if (mode == 45) {
        // OLMAPI32's MAPISendMail -> HrConvertMessageToUnicode -> HrConvertFileDescToUnicode:
        // the descriptor converter's failure landing pad calls FreeFileDescW(count, p) and then
        // free(p), while FreeFileDescW already released p itself (it frees each element's two
        // strings and then the array). One case per process so a fault cannot mask the others.
        // Field offsets come from the module's own instructions: MapiMessage is 96 bytes with
        // ulReserved+0, five strings at +8..+28, flFlags+30, lpOriginator+38, nRecipCount+40,
        // lpRecips+48, nFileCount+50, lpFiles+58; MapiFileDesc is 40 bytes with
        // lpszPathName+10 and lpszFileName+18 (the W twin uses the same offsets).
        g_soft = 0;
        HMODULE ho = GetModuleHandleA("OLMAPI32.dll");
        if (!ho) ho = LoadLibraryExA("OLMAPI32.dll", nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        typedef unsigned long (STDAPICALLTYPE *PFN_SENDMAIL)(void *, unsigned long long, void *,
                                                             unsigned long, unsigned long);
        PFN_SENDMAIL pSend = (PFN_SENDMAIL)GetProcAddress(ho, "MAPISendMail");
        printf("send=%p\n", (void *)pSend); fflush(stdout);
        if (!pSend) { printf("NOSEND\n"); return 12; }
        int cs = getenv("CRTF_CASE") ? atoi(getenv("CRTF_CASE")) : 1;
        static unsigned char msg[96];
        static unsigned char fd[40], fd2[40];
        static char badn[] = "\xED\xA0\x80";        // UTF-8 encoding of a lone surrogate half
        static char badp[] = "\xC0\x80";            // overlong NUL, also untranslatable
        static char goodn[] = "note.txt";
        static char goodp[] = "C:\\tmp";
        memset(msg, 0, sizeof(msg));
        memset(fd, 0, sizeof(fd)); memset(fd2, 0, sizeof(fd2));
        *(unsigned long *)(msg + 0x00) = 65001;     // ulReserved == 65001 selects CP_UTF8
        *(unsigned long *)(msg + 0x40) = 0;         // nRecipCount
        unsigned long long nf = (cs == 3) ? 2 : 1;
        *(unsigned long *)(msg + 0x50) = (unsigned long)nf;
        *(void **)(msg + 0x58) = fd;
        if (cs == 1) { *(char **)(fd + 0x18) = badn; }                 // file name fails
        else if (cs == 2) { *(char **)(fd + 0x18) = goodn; *(char **)(fd + 0x10) = goodp;
                            *(char **)(msg + 0x28) = badn; }           // message field fails first
        else if (cs == 3) { *(char **)(fd + 0x18) = goodn; *(void **)(msg + 0x58) = fd;
                            *(char **)(fd2 + 0x10) = badp; *(void **)(fd + 0x20) = nullptr;
                            // second descriptor is fd+40: place the bad path there
                            *(char **)(fd + 40 - 40 + 0x10) = goodp; }
        else if (cs == 4) { *(char **)(fd + 0x10) = badp; }             // path name fails
        else if (cs == 5) { *(char **)(fd + 0x18) = goodn; *(char **)(fd + 0x10) = goodp; } // all valid
        // HrConvertStringToWideChar's other negative return is its own malloc(2*cch) failing,
        // which lands the caller on the same cleanup pad; CRTF_PRESSURE reserves (but does not
        // commit) most of the address space so that allocation is the one that fails.
        char *held = nullptr;
        if (getenv("CRTF_PRESSURE")) {
            size_t gb = (size_t)strtoul(getenv("CRTF_PRESSURE"), nullptr, 10);
            held = (char *)VirtualAlloc(nullptr, gb << 30, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            printf("PRESSURE gb=%lu held=%p\n", (unsigned long)gb, (void *)held);
            if (held) memset(held, 1, 4096);
            fflush(stdout);
        }
        printf("CASE %d calling MAPISendMail(lhSession=0, ulUIParam=0, flFlags=0xC)\n", cs);
        fflush(stdout);
        unsigned long hr = 0;
        __try {
            hr = pSend(nullptr, 0, msg, 0xC, 0);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            printf("EXC code=%08x\n", (unsigned)GetExceptionCode()); fflush(stdout);
            return 20;
        }
        printf("CASE %d returned hr=%08x\n", cs, (unsigned)hr);
        fflush(stdout);
        return 0;
    }
    if (mode == 43) {
        // OUTLMIME's Ess*DecodeEx driven through a decode-parameter struct that hands the callee
        // OUR allocator. Every block the callee requests is placed so that its last byte is the
        // last committed byte of a region followed by an uncommitted page: a write one past the
        // size the callee itself asked for faults immediately, with the faulting address.
        // The same table makes a release of an unknown or already-released block visible at the
        // allocator boundary (double free / invalid free), which the heap's own metadata checks
        // only notice later and only if they run at all.
        g_soft = 1;
        AddVectoredExceptionHandler(1, VehReport);
        HMODULE hm3 = LoadLibraryExA("OUTLMIME.dll", nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!hm3)
            hm3 = LoadLibraryExA("C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLMIME.dll",
                                 nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        printf("OUTLMIME=%p\n", (void *)hm3); fflush(stdout);
        if (!hm3) { printf("NOMOD\n"); return 12; }
        static const char *kd[] = { "EssContentHint", "EssReceiptRequest", "EssReceipt",
                                    "EssMLHistory", "EssSecurityLabel", "EssKeyExchPreference",
                                    "EssSignCertificate" };
        const int NKD = 7;
        PFN_DASEX pD3[8];
        for (int k = 0; k < NKD; k++) {
            char nm[80];
            _snprintf(nm, sizeof(nm) - 1, "%sDecodeEx", kd[k]);
            pD3[k] = (PFN_DASEX)GetProcAddress(hm3, nm);
            printf("K %d %s dec=%p\n", k, kd[k], (void *)pD3[k]);
        }

        struct GK { void *p; void *base; unsigned long n; int live; };  // live: 1=callee, 2=harness
        static GK gk[4096];
        static int gkn = 0;
        static long nalloc = 0, nfree = 0, nbad = 0, ndbl = 0, nmaxcb = 0, ngrow = 0,
                      nhf = 0, nover = 0;
        typedef void *(STDAPICALLTYPE *PA)(size_t);
        typedef void (STDAPICALLTYPE *PF)(void *);
        PA A3 = +[](size_t cb) -> void * {
            unsigned long n = (unsigned long)(cb ? cb : 1);
            InterlockedIncrement(&nalloc);
            if ((long)n > nmaxcb) nmaxcb = (long)n;
            unsigned long pay = (n + 0xFFFul) & ~0xFFFul;
            unsigned char *base = (unsigned char *)VirtualAlloc(nullptr, pay + 0x1000, MEM_RESERVE, PAGE_NOACCESS);
            if (!base) { InterlockedIncrement(&ngrow); return (unsigned char *)malloc(n); }
            if (!VirtualAlloc(base, pay, MEM_COMMIT, PAGE_READWRITE)) {
                VirtualFree(base, 0, MEM_RELEASE);
                InterlockedIncrement(&ngrow);
                return (unsigned char *)malloc(n);
            }
            unsigned char *p = base + pay - n;          // block ends flush at the guard page
            int s = gkn;
            if (s < 4096) { gkn++; } else { s = 4095; InterlockedIncrement(&ngrow); }
            gk[s].p = p; gk[s].base = base; gk[s].n = n; gk[s].live = 1;
            return p;
        };
        // A destination block for the fill pass: same flush-to-guard-page placement, but owned by
        // the harness, so the callee writing past the capacity we handed it faults at the guard.
        typedef void *(STDAPICALLTYPE *PH)(unsigned long);
        PH H3 = +[](unsigned long n0) -> void * {
            unsigned long n = n0 ? n0 : 1;
            unsigned long pay = (n + 0xFFFul) & ~0xFFFul;
            unsigned char *base = (unsigned char *)VirtualAlloc(nullptr, pay + 0x1000, MEM_RESERVE, PAGE_NOACCESS);
            if (!base || !VirtualAlloc(base, pay, MEM_COMMIT, PAGE_READWRITE)) {
                if (base) VirtualFree(base, 0, MEM_RELEASE);
                InterlockedIncrement(&ngrow);
                return (unsigned char *)malloc(n);
            }
            unsigned char *p = base + pay - n;
            int st = gkn;
            if (st < 4096) { gkn++; } else { st = 4095; InterlockedIncrement(&ngrow); }
            gk[st].p = p; gk[st].base = base; gk[st].n = n; gk[st].live = 2;
            return p;
        };
        PF F3 = +[](void *pv) {
            InterlockedIncrement(&nfree);
            int hit = -1;
            for (int i = 0; i < gkn; i++) if (gk[i].live && gk[i].p == pv) { hit = i; break; }
            if (hit < 0) {
                InterlockedIncrement(&nbad);
                printf("BADFREE p=%p n=%lu\n", pv, (unsigned long)nbad); fflush(stdout);
                return;
            }
            if (gk[hit].live == 2) {
                InterlockedIncrement(&nhf);   // the callee released a block whose owner is the caller
                printf("CALLEEFREECALLER p=%p n=%lu\n", pv, (unsigned long)nhf); fflush(stdout);
            }
            gk[hit].live = 0;
            unsigned char *base = (unsigned char *)gk[hit].base;
            unsigned long pay = (gk[hit].n + 0xFFFul) & ~0xFFFul;
            VirtualFree(base, 0, MEM_RELEASE);
        };
        // Release every live block directly: the detector must only ever fire for a release the
        // callee itself performs, so the harness never goes through F3.
        auto Sweep = +[]() -> unsigned long {
            unsigned long got = 0;
            for (int i = 0; i < gkn; i++) {
                if (!gk[i].live) continue;
                gk[i].live = 0;
                VirtualFree((unsigned char *)gk[i].base, 0, MEM_RELEASE);
                got++;
            }
            gkn = 0;        // every block of this record is gone; the table refills from slot 0
            return got;
        };
        struct MY_PARA { unsigned long cbSize; PA pfnAlloc; PF pfnFree; };
        static MY_PARA par3; par3.cbSize = (unsigned long)sizeof(MY_PARA); par3.pfnAlloc = A3; par3.pfnFree = F3;

        size_t fsz3 = 0; BYTE *fb3 = LoadBlob(argv[1], &fsz3);
        if (!fb3) { printf("NOINPUT\n"); return 11; }
        static const BYTE kGood[] = { 0x30,0x0B,0x06,0x09,0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x2E,0x01 };

        // calibration: which argument convention does the shipping caller use, and which one lets
        // a record get as far as the flattener at all. Nothing downstream is a reading until a
        // convention shows a non-zero allocation count (the callee actually ran).
        if (getenv("CRTF_CALIB")) {
            for (int k = 0; k < NKD; k++) {
                if (!pD3[k]) continue;
                for (int cv = 0; cv < 6; cv++) {
                    void *pv = nullptr; unsigned long nd = 0; int r = 0;
                    unsigned long fl = (cv & 1) ? 0x8000u : 0u;
                    void *pa = (cv & 2) ? (void *)&par3 : nullptr;
                    unsigned long bf = 256;
                    void *pre = A3(bf);
                    pv = pre;
                    if (cv & 4) { pv = nullptr; }
                    __try {
                        r = pD3[k](k, 0, (unsigned char *)kGood, sizeof(kGood), fl, pa, &pv, &nd);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        r = -1;
                        printf("CAL k=%d cv=%d code=%08x\n", k, cv, (unsigned)GetExceptionCode());
                        continue;
                    }
                    printf("CAL k=%d cv=%d fl=%X para=%d pre=%d rc=%d nd=%lu pv=%p nal=%ld nblk=%lu gle=%08x\n",
                           k, cv, fl, (cv & 2) ? 1 : 0, (cv & 4) ? 0 : 1, r, nd, pv, nalloc,
                           Sweep(), (unsigned)GetLastError());
                    fflush(stdout);
                }
            }
            printf("CALIB nal=%ld nmaxcb=%ld nfree=%ld nbad=%ld\n", nalloc, nmaxcb, nfree, nbad);
            fflush(stdout);
            return 0;
        }

        unsigned long recs3 = 0, ok3 = 0, flt3 = 0, maxal = 0;
        unsigned long perok[8] = { 0 }, perf[8] = { 0 }, perfill[8] = { 0 }, perfault[8] = { 0 }, nfill = 0;
        unsigned long nmax3 = getenv("CRTF_NMAX") ? strtoul(getenv("CRTF_NMAX"), nullptr, 10) : 200000;
        static const unsigned long dl[3] = { 0, 1, 64 };
        size_t off3 = 0;
        while (off3 + 1 < fsz3 && recs3 < nmax3) {
            size_t e1 = off3; while (e1 < fsz3 && fb3[e1] != '\n') e1++;
            if (e1 >= fsz3) break;
            long want = strtol((char *)fb3 + off3, nullptr, 10);
            size_t body = e1 + 1;
            if (want <= 0 || body + (size_t)want > fsz3) break;
            off3 = body + want;
            if (off3 < fsz3 && fb3[off3] == '\n') off3++;
            recs3++;
            for (int k = 0; k < NKD; k++) {
                if (!pD3[k]) continue;
                // pass 1: ask the callee what size it needs (0x8000 = the query shape the
                // in-module caller uses); nothing is written to a destination yet.
                void *qpv = nullptr; unsigned long qn = 0; int rq = 0;
                long before = nalloc, badb = nbad;
                __try {
                    rq = pD3[k](k, 0, fb3 + body, (ULONG)want, 0x8000, (void *)&par3, &qpv, &qn);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    flt3++; perf[k]++;
                    printf("!!!QFAULT r=%lu k=%d len=%ld code=%08x\n", recs3, k, want,
                           (unsigned)GetExceptionCode()); fflush(stdout);
                    Sweep(); continue;
                }
                if (nbad > badb) ndbl += (unsigned long)(nbad - badb);
                if (nalloc - before > maxal) maxal = (unsigned long)(nalloc - before);
                if (!rq || !qn || qn > (64u << 20)) { Sweep(); continue; }
                ok3++; perok[k]++;
                unsigned long need = qn;
                // pass 2: hand it OUR buffer of exactly that size (and two deliberate deltas) as
                // both the destination and the declared capacity, with the last byte of the block
                // sitting against an uncommitted page.
                for (int di = 0; di < 3; di++) {
                    unsigned long cap = need + dl[di];
                    unsigned char *buf = (unsigned char *)H3(cap);
                    if (!buf) continue;
                    memset(buf, 0xCC, cap);
                    void *pv = buf; unsigned long cb = cap; int r2 = 0;
                    long bad2 = nbad;
                    __try {
                        r2 = pD3[k](k, 0, fb3 + body, (ULONG)want, 0, (void *)&par3, &pv, &cb);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        flt3++; perfault[k]++;
                        printf("!!!RFault r=%lu k=%d len=%ld need=%lu cap=%lu code=%08x\n", recs3, k,
                               want, need, cap, (unsigned)GetExceptionCode()); fflush(stdout);
                        continue;   // Sweep() at the end of the record releases the block
                    }
                    if (nbad > bad2) ndbl += (unsigned long)(nbad - bad2);
                    perfill[k]++; nfill++;
                    unsigned long past = 0;
                    if (r2) {                       // did it write anything at or past the promised size?
                        for (unsigned long z = need; z < cap; z++) if (buf[z] != 0xCC) { past = cap - z; break; }
                    }
                    if (past) { nover++; printf("PASTW r=%lu k=%d len=%ld need=%lu cap=%lu d=%lu rc=%d cb=%lu past=%lu\n",
                                                 recs3, k, want, need, cap, dl[di], r2, cb, past); fflush(stdout); }
                    if ((recs3 % 251) == 0 && di == 0)
                        printf("FILL r=%lu k=%d len=%ld need=%lu d=%lu rc=%d cb=%lu gle=%08x\n",
                               recs3, k, want, need, dl[di], r2, cb, (unsigned)GetLastError());
                }
                Sweep();
            }
            if ((recs3 & 255) == 0) {
                printf("P r=%lu ok=%lu flt=%lu nal=%ld nbad=%ld nhf=%ld past=%lu\n",
                       recs3, ok3, flt3, nalloc, nbad, nhf, nover); fflush(stdout);
            }
        }
        for (int k = 0; k < NKD; k++)
            printf("PERK %d %s qok=%lu fills=%lu qfault=%lu rfault=%lu\n", k, kd[k],
                   perok[k], perfill[k], perf[k], perfault[k]);
        printf("ESS43 recs=%lu qok=%lu fills=%lu qfault2=%lu past=%lu allocs=%ld maxallocs=%lu maxreq=%ld frees=%ld badfree=%ld cfcreator=%ld ownbad=%ld fallback=%ld\n",
               recs3, ok3, nfill, flt3, nover, nalloc, maxal, nmaxcb, nfree, nbad, nhf, ndbl, ngrow);
        fflush(stdout);
        return 0;
    }
    if (mode == 25) {
        // Read-after-free detector. Holds references that were taken from the message BEFORE an
        // RTFSync rewrite (which runs ScGetWriteChunkProp -> DestroyChunk -> MAPIFreeBuffer on the
        // cached body chunk) and reads them AFTER the rewrite. Slot indices come from the in-service
        // build's own CIMessage IMessage vtable: 2=Release, 5=GetProps, 7=OpenProperty.
        HMODULE hl5 = GetModuleHandleA("OLMAPI32.dll");
        PFN_RTFSYNC pSync5 = (PFN_RTFSYNC)GetProcAddress(hl5, "RTFSync");
        PFN_OPENMSGSESS pSess5 = (PFN_OPENMSGSESS)GetProcAddress(hl5, "OpenIMsgSession");
        PFN_OPENMSGONI pOpen5 = (PFN_OPENMSGONI)GetProcAddress(hl5, "OpenIMsgOnIStg");
        PFN_ALLOCBUF pAB5 = (PFN_ALLOCBUF)GetProcAddress(hl5, "MAPIAllocateBuffer");
        PFN_ALLOCMORE pAM5 = (PFN_ALLOCMORE)GetProcAddress(hl5, "MAPIAllocateMore");
        PFN_FREEBUF pFB5 = (PFN_FREEBUF)GetProcAddress(hl5, "MAPIFreeBuffer");
        if (!pSync5 || !pSess5 || !pOpen5 || !g_pWrap) { printf("SEQEXPORTS\n"); return 12; }
        ULONG lo5 = 0, hi5 = 0;
        {
            IMAGE_DOS_HEADER *dh = (IMAGE_DOS_HEADER *)hl5;
            IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((BYTE *)hl5 + dh->e_lfanew);
            lo5 = (ULONG)nt->OptionalHeader.BaseOfCode; hi5 = lo5 + nt->OptionalHeader.SizeOfCode;
        }
        g_hVal = hl5; g_lo = lo5; g_hi = hi5;
        char pat5[1100];
        size_t bl5 = strlen(argv[1]);
        const char *sl5 = (bl5 && argv[1][bl5 - 1] == '\\') ? "" : "\\";
        _snprintf(pat5, sizeof(pat5) - 1, "%s%s*.msg", argv[1], sl5);
        WIN32_FIND_DATAA fd;
        HANDLE hF = FindFirstFileA(pat5, &fd);
        if (hF == INVALID_HANDLE_VALUE) { printf("NOFILES\n"); return 13; }
        IMalloc *pMalloc5 = nullptr;
        CoGetMalloc(MEMCTX_TASK, &pMalloc5);
        void *pSession5 = nullptr;
        printf("SESS hr=%08x\n", (unsigned)pSess5((void *)pMalloc5, 0, &pSession5)); fflush(stdout);
        unsigned long cnt = 0, opened5 = 0, props = 0, wraps = 0, syncs = 0, rfs = 0, bad5 = 0;
        unsigned long maxc = getenv("CRTF_MAX") ? strtoul(getenv("CRTF_MAX"), nullptr, 10) : 0;
        char *rb = (char *)malloc(1u << 16);
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            if (fd.cFileName[0] == '.' || fd.cFileName[0] == '_') continue;  /* AppleDouble ._x / scratch */
            if (maxc && cnt >= maxc) break;
            char full[1300];
            _snprintf(full, sizeof(full) - 1, "%s%s%s", argv[1], sl5, fd.cFileName);
            cnt++;
            WCHAR wp5[1100];
            MultiByteToWideChar(CP_ACP, 0, full, -1, wp5, 1090);
            IStorage *pStg5 = nullptr;
            HRESULT h5 = StgOpenStorageEx(wp5, STGM_READWRITE | STGM_SHARE_EXCLUSIVE, STGFMT_STORAGE, 0,
                                          nullptr, nullptr, __uuidof(IStorage), (void **)&pStg5);
            if (FAILED(h5) || !pStg5) continue;
            void *pMsg5 = nullptr;
            h5 = pOpen5(pSession5, (void *)pAB5, (void *)pAM5, (void *)pFB5, pMalloc5, nullptr,
                        pStg5, nullptr, 0, 0, &pMsg5);
            if (FAILED(h5) || !pMsg5) { pStg5->Release(); continue; }
            opened5++;
            void **vt5 = (void **)*((void ***)pMsg5);
            PFN_RELEASE rel5 = (PFN_RELEASE)vt5[2];
            PFN_OPENPROP op5 = (PFN_OPENPROP)vt5[7];
            if ((uintptr_t)rel5 < (uintptr_t)hl5 + lo5 || (uintptr_t)rel5 > (uintptr_t)hl5 + hi5
                || (uintptr_t)op5 < (uintptr_t)hl5 + lo5 || (uintptr_t)op5 > (uintptr_t)hl5 + hi5) {
                bad5++;
                printf("BAD5 %s rel=0x%llX op=0x%llX\n", fd.cFileName,
                       (unsigned long long)((uintptr_t)rel5 - (uintptr_t)hl5),
                       (unsigned long long)((uintptr_t)op5 - (uintptr_t)hl5)); fflush(stdout);
                pStg5->Release(); continue;
            }
            IUnknown *pUnk = nullptr;
            HRESULT opr = op5(pMsg5, 0x10090102u, &__uuidof(IStream), 0, 11, (void **)&pUnk);
            IStream *pRaw = nullptr;
            if (SUCCEEDED(opr) && pUnk) { pRaw = (IStream *)pUnk; props++; }
            IStream *pWrap = nullptr;
            ULONG wfl5 = (argc > 2) ? (ULONG)strtoul(argv[2], nullptr, 16) : 4u;
            HRESULT wrh = pRaw ? g_pWrap(pRaw, wfl5, &pWrap) : (HRESULT)0xE0000001;
            unsigned long hadRaw = pRaw ? 1u : 0u, hadWrap = 0;
            if (pRaw && SUCCEEDED(wrh) && pWrap) { wraps++; hadWrap = 1; }
            ULARGE_INTEGER tot5 = {};
            if (pWrap) {
                ULONG got5 = 0;
                do { got5 = 0; pWrap->Read(rb, 1u << 16, &got5); tot5.QuadPart += got5; } while (got5);
            }
            int upd5 = -1;
            HRESULT hs5 = pSync5(pMsg5, 2, &upd5);
            if (SUCCEEDED(hs5)) syncs++;
            if (pWrap) {  // stale reference used AFTER the rewrite
                LARGE_INTEGER z = {};
                pWrap->Seek(z, STREAM_SEEK_SET, nullptr);
                ULONG got5 = 0; rfs++;
                pWrap->Read(rb, 1u << 16, &got5);
                tot5.QuadPart += got5;
            }
            if (pRaw) { ULONG got5 = 0; rfs++; pRaw->Read(rb, 1u << 16, &got5); }
            printf("STEP %lu before stale raw read pRaw=%p\n", cnt, (void *)pRaw); fflush(stdout);
            if (pWrap) SafeRelease(pWrap, "wrap", cnt);
            if (pRaw) SafeRelease(pRaw, "raw", cnt);
            pRaw = nullptr; pWrap = nullptr;
            IUnknown *pUnk2 = nullptr;
            if (SUCCEEDED(op5(pMsg5, 0x10090102u, &__uuidof(IStream), 0, 11, (void **)&pUnk2))
                && pUnk2) {
                IStream *pRaw2 = (IStream *)pUnk2; IStream *pWrap2 = nullptr;
                if (SUCCEEDED(g_pWrap(pRaw2, wfl5, &pWrap2)) && pWrap2) {
                    ULONG got5 = 0; pWrap2->Read(rb, 1u << 16, &got5);
                    SafeRelease(pWrap2, "wrap2", cnt);
                }
                SafeRelease(pRaw2, "raw2", cnt);
            }
            hs5 = pSync5(pMsg5, 2, &upd5);
            printf("RAF %lu %s raw=%u wrap=%u opr=%08x wrh=%08x sync=%08x bytes=%lu\n", cnt, fd.cFileName,
                   hadRaw, hadWrap, (unsigned)opr, (unsigned)wrh, (unsigned)hs5,
                   (unsigned long)tot5.QuadPart); fflush(stdout);
            printf("STEP %lu before msg Release\n", cnt); fflush(stdout);
            rel5(pMsg5);
            printf("STEP %lu before stg Release\n", cnt); fflush(stdout);
            pStg5->Release();
            printf("STEP %lu carrier done\n", cnt); fflush(stdout);
        } while (FindNextFileA(hF, &fd));
        FindClose(hF);
        printf("RAFEND carriers=%lu opened=%lu props=%lu wraps=%lu syncs=%lu stale_reads=%lu bad=%lu badrel=%lu\n",
               cnt, opened5, props, wraps, syncs, rfs, bad5, g_badrel); fflush(stdout);
        return 0;
    }
    size_t cb = 0; BYTE *buf = nullptr;
    if (strcmp(argv[1], "-") != 0) {
        buf = LoadBlob(argv[1], &cb);
        if (!buf) { printf("READFAIL %s\n", argv[1]); return 5; }
    } else {
        cb = (size_t) fread(calloc(1, 1 << 20), 1, 1 << 20, stdin);
        buf = (BYTE *)realloc(buf, cb ? cb : 1);
    }
    printf("blob=%zu flags=%x chunk=%u mode=%d\n", cb, flags, chunk, mode);

    if (mode == 40) {
        g_soft = 1;
        if (getenv("CRTF_NOMAPI")) printf("NOMAPI\n");
        // MimeOleParseRfc822Address(cch, encType, psz, ADDRESSLIST*) -- exported, no COM object needed.
        // argv[1] = file with one address string per line (length-prefixed: "<len>\n<bytes>\n").
        HMODULE hm = LoadLibraryExA("OUTLMIME.dll", nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!hm) hm = LoadLibraryExA("C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLMIME.dll",
                                      nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        PFN_PARSE_ADDR pParse = (PFN_PARSE_ADDR)GetProcAddress(hm, "MimeOleParseRfc822Address");
        printf("OUTLMIME=%p parse=%p\n", (void *)hm, (void *)pParse);
        fflush(stdout);
        if (!pParse) { printf("NOPARSE\n"); return 10; }
        size_t fsz = 0; BYTE *fb = LoadBlob(argv[1], &fsz);
        if (!fb) { printf("NOINPUT\n"); return 11; }
        size_t off = 0; unsigned long n = 0, okc = 0, errc = 0;
        char *line = (char *)malloc(1u << 20);
        unsigned long nmax40 = getenv("CRTF_NMAX") ? strtoul(getenv("CRTF_NMAX"), nullptr, 10) : 5000000ul;
        while (off + 1 < fsz && n < nmax40) {
            size_t e1 = off; while (e1 < fsz && fb[e1] != '\n') e1++;
            if (e1 >= fsz) break;
            long want = strtol((char *)fb + off, nullptr, 10);
            size_t body = e1 + 1;
            if (want < 0 || body + (size_t)want > fsz) break;
            memcpy(line, (char *)fb + body, want);
            line[want] = 0;
            off = body + want;
            if (want && fb[body + want] == '\n') off = body + want + 1;
            if (want == 0) continue;
            unsigned char alist[512];
            memset(alist, 0, sizeof(alist));
            for (ULONG enc = 1; enc <= 3; enc++) {
                __try {
                    HRESULT hr2 = pParse((ULONG)want, enc, line, alist);
                    if (SUCCEEDED(hr2)) okc++; else errc++;
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    printf("FAULT rec=%lu off=%zu len=%ld enc=%lu code=%08x\n", n, off, want, enc,
                           (unsigned)GetExceptionCode());
                    fflush(stdout);
                }
                n++;
            }
            if ((n % 20000) == 0) { printf("PROG %lu ok=%lu err=%lu faults=%lu\n", n, okc, errc, g_faults); fflush(stdout); }
        }
        printf("ADDRCASES n=%lu ok=%lu err=%lu faults=%lu\nEND addr\n", n, okc, errc, g_faults);
        fflush(stdout);
        return 0;
    }
    if (mode == 11 || mode == 12) {
        // TNEF (winmail.dat) sweep, all records inside ONE process: OpenTnefStreamEx ->
        // HrGetOpenTnefStream -> drain the body stream -> release. Cross-record heap reuse plus
        // per-record attribution.
        g_soft = 1;
        HMODULE hl6 = GetModuleHandleA("OLMAPI32.dll");
        PFN_OPEN_TNEF pOpen6 = (PFN_OPEN_TNEF)GetProcAddress(hl6, "OpenTnefStreamEx");
        PFN_GET_TNEF_STM pGet6 = (PFN_GET_TNEF_STM)GetProcAddress(hl6, "HrGetOpenTnefStream");
        printf("tnef open=%p get=%p\n", (void *)pOpen6, (void *)pGet6); fflush(stdout);
        if (!pOpen6) { printf("NOTNEFEXPORT\n"); return 7; }
        size_t fsz6 = 0; BYTE *fb6 = LoadBlob(argv[1], &fsz6);
        if (!fb6) { printf("NOINPUT\n"); return 11; }
        // OpenTnefStreamEx(TNEF_DECODE) writes into a target message; without one every record
        // returns 0x80070057. Reuse ONE message across the whole corpus so the property arrays are
        // also exercised across many successive decodes.
        void *pMsgT = nullptr; IStorage *pStgT = nullptr; IMalloc *pMlT = nullptr;
        void *pSessT = nullptr;
        const char *bm = getenv("CRTF_BASEMSG");
        PFN_OPENMSGSESS pS6 = (PFN_OPENMSGSESS)GetProcAddress(hl6, "OpenIMsgSession");
        PFN_OPENMSGONI pO6 = (PFN_OPENMSGONI)GetProcAddress(hl6, "OpenIMsgOnIStg");
        PFN_ALLOCBUF pA6 = (PFN_ALLOCBUF)GetProcAddress(hl6, "MAPIAllocateBuffer");
        PFN_ALLOCMORE pAM6 = (PFN_ALLOCMORE)GetProcAddress(hl6, "MAPIAllocateMore");
        PFN_FREEBUF pFB6 = (PFN_FREEBUF)GetProcAddress(hl6, "MAPIFreeBuffer");
        if (bm && pS6 && pO6) {
            CoGetMalloc(MEMCTX_TASK, (IMalloc **)&pMlT);
            WCHAR wb[1100]; MultiByteToWideChar(CP_ACP, 0, bm, -1, wb, 1090);
            HRESULT hb = StgOpenStorageEx(wb, STGM_READWRITE | STGM_SHARE_EXCLUSIVE, STGFMT_STORAGE,
                                          0, nullptr, nullptr, __uuidof(IStorage), (void **)&pStgT);
            pS6((void *)pMlT, 0, &pSessT);
            HRESULT hg = pO6(pSessT, (void *)pA6, (void *)pAM6, (void *)pFB6, pMlT, nullptr,
                             pStgT, nullptr, 0, 0, &pMsgT);
            printf("TBASEMSG stg=%08x sess=%p msg_hr=%08x msg=%p\n", (unsigned)hb, pSessT,
                   (unsigned)hg, pMsgT); fflush(stdout);
        } else printf("TBASEMSG none (set CRTF_BASEMSG)\n");
        size_t off6 = 0; unsigned long n6 = 0, ok6 = 0, err6 = 0, got6 = 0, drains = 0;
        // Modules that a corpus file pulls in (mso, oart, ...) only appear after the install point, so
        // the observed set has to be re-taken periodically or their blocks look untracked.
        unsigned long resc = getenv("CRTF_RESCAN") ? strtoul(getenv("CRTF_RESCAN"), nullptr, 10) : 0;
        unsigned long nmax6 = getenv("CRTF_NMAX") ? strtoul(getenv("CRTF_NMAX"), nullptr, 10) : 200000;
        char *rec6 = (char *)malloc(64u << 20);
        ULONG fl6 = (argc > 2) ? (ULONG)strtoul(argv[2], nullptr, 16) : 0u;
        while (off6 + 1 < fsz6 && n6 < nmax6) {
            if (resc && (n6 % resc) == 0) InstallAllocHooks("all", 1);
            size_t e6 = off6; while (e6 < fsz6 && fb6[e6] != '\n') e6++;
            if (e6 >= fsz6) break;
            long want6 = strtol((char *)fb6 + off6, nullptr, 10);
            size_t body6 = e6 + 1;
            if (want6 < 0 || body6 + (size_t)want6 > fsz6) break;
            if ((size_t)want6 > (64u << 20)) break;
            memcpy(rec6, (char *)fb6 + body6, want6);
            off6 = body6 + want6;
            if (off6 < fsz6 && fb6[off6] == '\n') off6++;
            IStream *ps = nullptr;
            if (FAILED(CreateStreamOnHGlobal(nullptr, TRUE, &ps)) || !ps) { n6++; continue; }
            ULONG put6 = 0;
            ps->Write((void *)rec6, (ULONG)want6, &put6);
            LARGE_INTEGER z6; z6.QuadPart = 0; ps->Seek(z6, STREAM_SEEK_SET, nullptr);
            void *hT = nullptr;
            // 8-arg shape (mapitnef.cxx as used by the 2026-09-03 harness): (null, stream, name,
            // flags=0 == TNEF_DECODE here, message, key, addressBook=nullptr, &handle)
            HRESULT h6 = ((PFN_OPEN_TNEF8)pOpen6)(nullptr, ps, (char *)"winmail.dat", fl6,
                                                  pMsgT, 0x1234, nullptr, &hT);
            if (SUCCEEDED(h6) && hT) { ok6++; } else { err6++; }
            if (SUCCEEDED(h6) && hT && pGet6) {
                IStream *pb = nullptr;
                HRESULT h7 = pGet6(hT, &pb);
                if (SUCCEEDED(h7) && pb) {
                    got6++;
                    BYTE *db = (BYTE *)malloc(1u << 16); ULONG gg = 0, k = 0;
                    while (k < 8000 && SUCCEEDED(pb->Read(db, 1u << 16, &gg)) && gg) { drains++; k++; }
                    free(db);
                    ((PFN_RELEASE)*(void **)*((void ***)pb))(pb);
                }
            }
            static int dumped = 0;
            if (mode == 12 && !dumped) {
                dumped = 1;
                const char *cands[] = { "TNEFExtractProps", "TNEFFinish", "TNEFAddProps", "TNEFSetProps",
                    "TNEFOpenTaggedBody", "TNEFClose", "TNEFInit", "TNEFInitMapi", "TNEFOutTnefStream",
                    "TNEFOpenStream", "TNEFAbort", "TNEFCommit", "TNEFDecodeBuffer", "TNEFGetNextAttr",
                    "TNEFMapHandle", "HrTNEFExtractProps", "TNEFSetFT", "TNEFGetLastError" };
                printf("TNEXPORTS:");
                for (int q = 0; q < 18; q++) {
                    void *v = GetProcAddress(g_hOlm, cands[q]);
                    printf(" %s=%s", cands[q], v ? "yes" : "no");
                }
                printf("\n"); fflush(stdout);
            }
            unsigned long ex4 = 0, fi5 = 0, bod = 0;
            if (mode == 12 && SUCCEEDED(h6) && hT) {
                // hT -> obj, whose vtable is ImplOpenTnefStream (the factory). The ITnef interface
                // comes from QueryInterface on it; IID read out of the module's own data (IID_ITNEF).
                static const GUID iidTnef = { 0x00020319, 0x0000, 0x0000,
                    { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
                void *facT = *(void **)hT;
                void *objT = nullptr;
                if (facT) {
                    PFN_QI pQiT = (PFN_QI) * (void **)*((void ***)facT);
                    ULONG loQ = 0, hiQ = 0;
                    IMAGE_DOS_HEADER *dq = (IMAGE_DOS_HEADER *)g_hOlm;
                    IMAGE_NT_HEADERS *nq = (IMAGE_NT_HEADERS *)((BYTE *)g_hOlm + dq->e_lfanew);
                    loQ = nq->OptionalHeader.BaseOfCode; hiQ = loQ + nq->OptionalHeader.SizeOfCode;
                    if ((uintptr_t)pQiT >= (uintptr_t)g_hOlm + loQ && (uintptr_t)pQiT <= (uintptr_t)g_hOlm + hiQ)
                        pQiT(facT, &iidTnef, &objT);
                }
                if (!objT && facT) {
                    // MAPI multi-interface objects keep the secondary interface pointer in an early
                    // field; accept a candidate only if its whole slot table lands inside .text.
                    ULONG loS = 0, hiS = 0;
                    IMAGE_DOS_HEADER *ds = (IMAGE_DOS_HEADER *)g_hOlm;
                    IMAGE_NT_HEADERS *ns = (IMAGE_NT_HEADERS *)((BYTE *)g_hOlm + ds->e_lfanew);
                    loS = ns->OptionalHeader.BaseOfCode; hiS = loS + ns->OptionalHeader.SizeOfCode;
                    for (int fld = 1; fld <= 6 && !objT; fld++) {
                        void *cand = *(void **)((char *)facT + 8 * fld);
                        if (!cand) continue;
                        void **cvt = (void **)*(uintptr_t *)cand;
                        int all = 1;
                        for (int q = 0; q < 10; q++) {
                            uintptr_t f = (uintptr_t)cvt[q];
                            if (f < (uintptr_t)g_hOlm + loS || f > (uintptr_t)g_hOlm + hiS) { all = 0; break; }
                        }
                        if (all) { objT = cand; printf("TPROBE field=%d vt_rva=0x%llX\n", fld,
                                    (unsigned long long)((uintptr_t)cvt - (uintptr_t)g_hOlm)); fflush(stdout); }
                    }
                }
                void **vtT = objT ? (void **)*((void ***)objT) : nullptr;
                ULONG lo6 = 0, hi6 = 0;
                IMAGE_DOS_HEADER *d6 = (IMAGE_DOS_HEADER *)g_hOlm;
                IMAGE_NT_HEADERS *n6h = (IMAGE_NT_HEADERS *)((BYTE *)g_hOlm + d6->e_lfanew);
                lo6 = n6h->OptionalHeader.BaseOfCode; hi6 = lo6 + n6h->OptionalHeader.SizeOfCode;
                uintptr_t vtR = (uintptr_t)vtT - (uintptr_t)g_hOlm;
                int good = vtT && vtR < 0x900000;
                PFN_TNEF_CALL pEx = good ? (PFN_TNEF_CALL)vtT[4] : nullptr;
                PFN_TNEF_CALL pFin = good ? (PFN_TNEF_CALL)vtT[5] : nullptr;
                PFN_OPEN_TAGGED_BODY pBody = good ? (PFN_OPEN_TAGGED_BODY)vtT[6] : nullptr;
                PFN_RELEASE pRelT = good ? (PFN_RELEASE)vtT[2] : nullptr;
                int inText = pEx && pFin && pRelT
                    && (uintptr_t)pEx >= (uintptr_t)g_hOlm + lo6 && (uintptr_t)pEx <= (uintptr_t)g_hOlm + hi6
                    && (uintptr_t)pFin >= (uintptr_t)g_hOlm + lo6 && (uintptr_t)pFin <= (uintptr_t)g_hOlm + hi6
                    && (uintptr_t)pRelT >= (uintptr_t)g_hOlm + lo6 && (uintptr_t)pRelT <= (uintptr_t)g_hOlm + hi6;
                printf("TVIEW %lu fac=%p obj=%p vt_rva=0x%llX ex=0x%llX fin=0x%llX body=0x%llX rel=0x%llX ok=%d\n",
                       n6, facT, objT, (unsigned long long)vtR,
                       pEx ? (unsigned long long)((uintptr_t)pEx - (uintptr_t)g_hOlm) : 0ull,
                       pFin ? (unsigned long long)((uintptr_t)pFin - (uintptr_t)g_hOlm) : 0ull,
                       pBody ? (unsigned long long)((uintptr_t)pBody - (uintptr_t)g_hOlm) : 0ull,
                       pRelT ? (unsigned long long)((uintptr_t)pRelT - (uintptr_t)g_hOlm) : 0ull, inText);
                fflush(stdout);
                if (inText) {
                    void *prob = nullptr;
                    HRESULT he = pEx(objT, 0, nullptr, &prob);
                    ex4++;
                    void *prob2 = nullptr;
                    HRESULT hf = pFin(objT, 0, nullptr, &prob2);
                    fi5++;
                    IStream *pB = nullptr;
                    ULONG kk = 0;
                    HRESULT hb = pBody ? pBody(objT, pMsgT, 0, &pB) : (HRESULT)0xE0000002;
                    if (SUCCEEDED(hb) && pB) {
                        bod++;
                        BYTE *dbb = (BYTE *)malloc(1u << 16); ULONG gg = 0;
                        while (kk < 4000 && SUCCEEDED(pB->Read(dbb, 1u << 16, &gg)) && gg) kk++;
                        kk *= (1u << 16);
                        free(dbb);
                        PFN_RELEASE pRelB = (PFN_RELEASE) * (void **)*((void ***)pB);
                        if ((uintptr_t)pRelB >= (uintptr_t)g_hOlm + lo6 && (uintptr_t)pRelB <= (uintptr_t)g_hOlm + hi6)
                            pRelB(pB);
                    }
                    printf("TREC %lu len=%ld open=%08x extract=%08x finish=%08x body=%08x read=%lu vt=0x%llX\n",
                           n6, want6, (unsigned)h6, (unsigned)he, (unsigned)hf, (unsigned)hb, kk,
                           (unsigned long long)vtR); fflush(stdout);
                    pRelT(objT);
                } else {
                    printf("TNEFVTBL_BAD %lu vt=%p ex=%p fin=%p rel=%p\n", n6, (void *)vtT,
                           (void *)pEx, (void *)pFin, (void *)pRelT); fflush(stdout);
                }
            }
            if ((n6 % 50) == 0) printf("TPROG %lu ok=%lu err=%lu got=%lu ex=%lu fin=%lu faults=%lu\n",
                                       n6, ok6, err6, got6, ex4, fi5, g_faults);
            if (!(mode == 12 && SUCCEEDED(h6) && hT)) {
                printf("TREC %lu len=%ld open=%08x\n", n6, want6, (unsigned)h6); fflush(stdout);
            }
            ps->Release();
            n6++;
        }
        printf("TNEFCASES n=%lu ok=%lu err=%lu gotstream=%lu drains=%lu faults=%lu\n",
               n6, ok6, err6, got6, drains, g_faults); fflush(stdout);
        return 0;
    }
    if (mode == 30) {
        // TNEF decode with a real IMessage as the property sink:
        //   base .msg -> IMessage ; file -> IStream ; OpenTnefStream(service,stream,&h,name,flags,msg,advise)
        HMODULE hl = GetModuleHandleA("OLMAPI32.dll");
        PFN_OPEN_TNEF_MSG pOpenT = (PFN_OPEN_TNEF_MSG)GetProcAddress(hl, "OpenTnefStream");
        PFN_OPENMSGSESS pSess = (PFN_OPENMSGSESS)GetProcAddress(hl, "OpenIMsgSession");
        PFN_OPENMSGONI pOpenI = (PFN_OPENMSGONI)GetProcAddress(hl, "OpenIMsgOnIStg");
        PFN_ALLOCBUF pAB = (PFN_ALLOCBUF)GetProcAddress(hl, "MAPIAllocateBuffer");
        PFN_ALLOCMORE pAM = (PFN_ALLOCMORE)GetProcAddress(hl, "MAPIAllocateMore");
        PFN_FREEBUF pFB = (PFN_FREEBUF)GetProcAddress(hl, "MAPIFreeBuffer");
        PFN_GET_TNEF_STM pGetStm = (PFN_GET_TNEF_STM)GetProcAddress(hl, "HrGetOpenTnefStream");
        if (!pOpenT || !pSess || !pOpenI) { printf("TNEFEXPORTS t=%p sess=%p i=%p\n", (void *)pOpenT, (void *)pSess, (void *)pOpenI); return 9; }
        const char *msgpath = getenv("CRTF_MSG");
        if (!msgpath) msgpath = "C:\\crtf\\base_valid.msg";
        WCHAR wpath[1024];
        MultiByteToWideChar(CP_ACP, 0, msgpath, -1, wpath, 1020);
        void *pSession = nullptr;
        pSess(nullptr, 0, &pSession);
        IStorage *pStg = nullptr;
        HRESULT hs = StgOpenStorageEx(wpath, STGM_READWRITE | STGM_SHARE_EXCLUSIVE | STGM_DIRECT,
                                      STGFMT_STORAGE, 0, nullptr, nullptr, __uuidof(IStorage), (void **)&pStg);
        printf("MSG_STG hr=%08x\n", (unsigned)hs);
        IMalloc *pMalloc = nullptr; CoGetMalloc(MEMCTX_TASK, &pMalloc);
        void *pMsg = nullptr;
        hs = pOpenI(pSession, (void *)pAB, (void *)pAM, (void *)pFB, pMalloc, nullptr, pStg, nullptr, 0, 0, &pMsg);
        printf("MSG_OPEN hr=%08x msg=%p\n", (unsigned)hs, pMsg);
        // the tnef blob goes through its own ole32 stream (this mode runs before pSrc exists)
        IStream *pT = nullptr;
        CreateStreamOnHGlobal(nullptr, TRUE, &pT);
        ULONG putT = 0;
        pT->Write(buf, (ULONG)cb, &putT);
        LARGE_INTEGER zT; zT.QuadPart = 0;
        pT->Seek(zT, STREAM_SEEK_SET, nullptr);
        HRESULT hr = S_OK;
        void *hT = nullptr;
        hr = pOpenT(nullptr, pT, &hT, "tnef", flags, pMsg, nullptr);
        printf("OPENTNEF hr=%08x h=%p\n", (unsigned)hr, hT);
        fflush(stdout);
        if (SUCCEEDED(hr) && hT && pGetStm) {
            IStream *pBody = nullptr;
            HRESULT h2 = pGetStm(hT, &pBody);
            printf("GETSTM hr=%08x p=%p\n", (unsigned)h2, (void *)pBody);
            if (SUCCEEDED(h2) && pBody) {
                BYTE *b3 = (BYTE *)malloc(chunk + 32);
                ULONG g3 = 0, t3 = 0, n3 = 0;
                while (n3 < 20000 && SUCCEEDED(pBody->Read(b3, chunk, &g3)) && g3) { t3 += g3; ++n3; }
                printf("TNEFBODY n=%u total=%u\n", n3, t3);
                pBody->Release();
            }
        }
        printf("END tnefmsg\n"); fflush(stdout);
        if (pMsg) ((HRESULT (STDMETHODCALLTYPE *)(void *, REFIID, void **))(*(void ***)pMsg)[0])(pMsg, IID_IUnknown, nullptr);
        if (pStg) pStg->Release();
        pT->Release();
        return 0;
    }
    if (mode == 20 || mode == 21) {
        // .msg -> IStorage -> IMessage -> exported RTFSync(message, flags, &updated)
        //   RTFSync -> RTFSyncCpid -> ScFullRTFSync / ScComputeBodyFromRTF -> ScUpdateRTF (chunk + CRC map + body tag)
        HMODULE hl = GetModuleHandleA("OLMAPI32.dll");
        PFN_RTFSYNC pSync = (PFN_RTFSYNC)GetProcAddress(hl, "RTFSync");
        PFN_OPENMSGSESS pSess = (PFN_OPENMSGSESS)GetProcAddress(hl, "OpenIMsgSession");
        PFN_OPENMSGONI pOpen = (PFN_OPENMSGONI)GetProcAddress(hl, "OpenIMsgOnIStg");
        PFN_ALLOCBUF pAB = (PFN_ALLOCBUF)GetProcAddress(hl, "MAPIAllocateBuffer");
        PFN_ALLOCMORE pAM = (PFN_ALLOCMORE)GetProcAddress(hl, "MAPIAllocateMore");
        PFN_FREEBUF pFB = (PFN_FREEBUF)GetProcAddress(hl, "MAPIFreeBuffer");
        if (!pSync || !pSess || !pOpen || !pAB || !pAM || !pFB) {
            printf("MAPIEXPORTS sync=%p sess=%p open=%p ab=%p\n", (void *)pSync, (void *)pSess, (void *)pOpen, (void *)pAB);
            return 8;
        }
        void *pSession = nullptr;
        HRESULT h = pSess(nullptr, 0, &pSession);
        printf("OpenIMsgSession hr=%08x\n", (unsigned)h);
        IStorage *pStg = nullptr;
        WCHAR wpath[1024];
        MultiByteToWideChar(CP_ACP, 0, argv[1], -1, wpath, 1020);
        h = StgOpenStorageEx(wpath, STGM_READ | STGM_SHARE_DENY_WRITE, STGFMT_STORAGE, 0, nullptr, nullptr,
                             __uuidof(IStorage), (void **)&pStg);
        printf("StgOpenStorageEx hr=%08x stg=%p\n", (unsigned)h, (void *)pStg);
        if (SUCCEEDED(h) && pStg) {
            IMalloc *pMalloc = nullptr;
            CoGetMalloc(MEMCTX_TASK, &pMalloc);
            void *pMsg = nullptr;
            h = pOpen(pSession, (void *)pAB, (void *)pAM, (void *)pFB, pMalloc, nullptr, pStg,
                      nullptr, 0, 0, &pMsg);
            printf("OpenIMsgOnIStg hr=%08x msg=%p\n", (unsigned)h, pMsg);
            if (SUCCEEDED(h) && pMsg) {
                for (ULONG fl = (flags ? flags : 1); fl <= (flags ? flags : 3); fl++) {
                    int updated = -1;
                    HRESULT h2 = pSync(pMsg, fl, &updated);
                    printf("RTFSYNC flags=%lu hr=%08x updated=%d\n", fl, (unsigned)h2, updated);
                    fflush(stdout);
                    if (flags) break;
                }
            }
            if (pMalloc) pMalloc->Release();
            pStg->Release();
        }
        printf("END rtfsync\n"); fflush(stdout);
        return 0;
    }
    IStream *pSrc = nullptr;
    HRESULT hr = CreateStreamOnHGlobal(nullptr, TRUE, &pSrc);
    if (FAILED(hr)) { printf("CREATESTREAM hr=%08x\n", (unsigned)hr); return 6; }
    ULONG put = 0;
    hr = pSrc->Write(buf, (ULONG)cb, &put);
    printf("SRCWRITE hr=%08x put=%u\n", (unsigned)hr, put);
    LARGE_INTEGER zero; zero.QuadPart = 0;
    pSrc->Seek(zero, STREAM_SEEK_SET, nullptr);

    if (mode == 9 || mode == 10) {
        HMODULE hl = GetModuleHandleA("OLMAPI32.dll");
        PFN_OPEN_TNEF pOpen = (PFN_OPEN_TNEF)GetProcAddress(hl, "OpenTnefStreamEx");
        PFN_GET_TNEF_STM pGet = (PFN_GET_TNEF_STM)GetProcAddress(hl, "HrGetOpenTnefStream");
        if (!pOpen) { printf("NOTNEFEXPORT\n"); return 7; }
        void *hTnef = nullptr;
        hr = pOpen(pSrc, &hTnef, "tnef", flags, nullptr, nullptr, nullptr);
        printf("OPENTNEF hr=%08x h=%p\n", (unsigned)hr, hTnef);
        fflush(stdout);
        if (SUCCEEDED(hr) && hTnef && pGet && mode == 10) {
            IStream *pBody = nullptr;
            HRESULT h2 = pGet(hTnef, &pBody);
            printf("GETSTM hr=%08x p=%p\n", (unsigned)h2, (void *)pBody);
            if (SUCCEEDED(h2) && pBody) {
                BYTE *b2 = (BYTE *)malloc(chunk + 32);
                ULONG g2 = 0, t2 = 0, n2 = 0;
                while (n2 < 40000 && SUCCEEDED(pBody->Read(b2, chunk, &g2)) && g2) { t2 += g2; ++n2; }
                printf("BODYREADS n=%u total=%u\n", n2, t2);
                pBody->Release();
            }
        }
        printf("END tnef\n"); fflush(stdout);
        pSrc->Release();
        return 0;
    }
    IStream *pOut = nullptr;
    hr = g_pWrap(pSrc, flags, &pOut);
    printf("WRAP hr=%08x out=%p\n", (unsigned)hr, (void *)pOut);
    if (FAILED(hr) || !pOut) { printf("END wrapfail\n"); return 0; }

    BYTE *rb = (BYTE *)malloc(chunk + 32);
    ULONG total = 0, reads = 0, rc = 0;
    if (mode == 1) {
        unsigned seed = (unsigned)(cb * 2654435761u + flags);
        for (int k = 0; k < 64; k++) {
            seed = seed * 1103515245u + 12345u;
            LARGE_INTEGER pos; pos.QuadPart = (LONGLONG)(seed % 0x20000u);
            ULARGE_INTEGER g;
            hr = pOut->Seek(pos, (k % 3 == 0) ? STREAM_SEEK_SET : ((k % 3 == 1) ? STREAM_SEEK_CUR : STREAM_SEEK_END), &g);
            if (SUCCEEDED(hr)) {
                ULONG got = 0;
                hr = pOut->Read(rb, chunk, &got);
                total += got;
                printf("SEEK k=%d rc=%08x pos=%lld read=%08x got=%u\n", k, (unsigned)hr, (long long)g.QuadPart, (unsigned)hr, got);
            } else {
                printf("SEEK k=%d rc=%08x\n", k, (unsigned)hr);
            }
        }
    } else if (mode == 2) {
        STATSTG st;
        hr = pOut->Stat(&st, STATFLAG_NONAME);
        printf("STAT hr=%08x size=%lld\n", (unsigned)hr, (long long)st.cbSize.QuadPart);
        IStream *pClone = nullptr;
        hr = pOut->Clone(&pClone);
        printf("CLONE hr=%08x p=%p\n", (unsigned)hr, (void *)pClone);
        if (pClone) {
            ULONG got = 0;
            while (SUCCEEDED(pClone->Read(rb, chunk, &got)) && got) { total += got; if (++reads > 20000) break; }
            pClone->Release();
        }
        LARGE_INTEGER p0; p0.QuadPart = 0; pOut->Seek(p0, STREAM_SEEK_SET, nullptr);
    }
    while (reads < 40000) {
        ULONG got = 0;
        hr = pOut->Read(rb, chunk, &got);
        ++reads;
        total += got;
        if (FAILED(hr)) { rc = (unsigned)hr; break; }
        if (!got) break;
    }
    printf("READS n=%u total=%u lasthr=%08x\n", reads, total, rc);
    fflush(stdout);
    pOut->Release();
    pSrc->Release();
    if (g_pWrapEx) printf("HAS_EX\n");
    if (mode == 3) {
        // second pass through WrapCompressedRTFStreamEx with the same blob
        IStream *p2 = nullptr;
        pSrc->Seek(zero, STREAM_SEEK_SET, nullptr);
        hr = g_pWrapEx(pSrc, flags, &p2);
        printf("WRAPX hr=%08x\n", (unsigned)hr);
        if (SUCCEEDED(hr) && p2) {
            ULONG got = 0, n = 0, t = 0;
            while (n < 40000 && SUCCEEDED(p2->Read(rb, chunk, &got)) && got) { t += got; ++n; }
            printf("READSX n=%u total=%u\n", n, t);
            p2->Release();
        }
    }
    printf("END ok\n");
    fflush(stdout);
    return 0;
}
