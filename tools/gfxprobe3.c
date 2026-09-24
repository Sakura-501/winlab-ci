/* gfxprobe3.c - in-process driver for Office GFX.dll EMF / EMF+ / image decoding.
 *
 * GFX.DLL ships in Office root\Office16 and delay-loads MSO.dll; it exports
 *   GEL::IMetafilePlus::Create(IStream*)   (EMF / EMF+ metafile parse)
 *   GEL::IImage::Create(IStream*)          (GEL PNG/GIF/JPEG/TIFF blip decode)
 * Both return an Office smart pointer by value, so two ABI hypotheses are tried.
 *
 * modes:
 *   selftest                          - arm proof: 1-byte write past a 64 B heap block
 *   init                              - print loader / config / ABI diagnostics
 *   probe  <file> [kind]              - one blob, both ABIs
 *   sweep  <dir> <kind> <abi> <start> <cap>   - batch, prints SUMMARY
 * kind = meta (default) | img ; abi = 1 (return-in-RAX) | 2 (hidden return ptr)
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void *(*PFN1)(void *);
typedef void  (*PFN2)(void *, void *);

static const char *NM_META =
    "?Create@IMetafilePlus@GEL@@SA?AV?$TCntPtr@UIMetafilePlus@GEL@@@Mso@@PEAUIStream@@@Z";
static const char *NM_IMAGE =
    "?Create@IImage@GEL@@SA?AV?$TCntPtr@UIImage@GEL@@@Ofc@@PEAUIStream@@@Z";
static const char *NM_INIT = "?FGfxInitialized@Immediate@Gfx@@YA_NXZ";
static const char *NM_GETCFG = "?GetConfig@Immediate@Gfx@@YAAEBVConfig@2@XZ";
static const char *NM_CFGINIT = "?ConfigInit@Immediate@Gfx@@YAXPEBVConfig@2@@Z";
static const char *NM_OSP = "?EnsureLoadOSpectre@Gfx@@YAXXZ";

typedef void *(*MEMSTREAM_FN)(const unsigned char *, unsigned int);
static MEMSTREAM_FN pMemStream;
static HMODULE g_gfx;
static void *g_fp[2];
static unsigned long g_which;
static int g_faults, g_throws;

static int readable(const void *p)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (!p) return 0;
    if (VirtualQuery((void *)p, &mbi, sizeof(mbi)) == 0) return 0;
    return mbi.State == MEM_COMMIT &&
           (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                           PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE));
}

static int obj_ok(void *o)
{
    void *vt;
    if (!readable(o)) return 0;
    vt = *(void **)o;
    if (!readable(vt)) return 0;
    if (!readable(*(void **)vt)) return 0;
    return 1;
}

static void irelease(void *obj)
{
    void **vt;
    if (!obj_ok(obj)) return;
    vt = *(void ***)obj;
    ((void (*)(void *))vt[2])(obj);
}

static void mod_of(void *addr, char *out, size_t cap)
{
    HMODULE m = NULL;
    out[0] = 0;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)addr, &m) && m) {
        WCHAR w[MAX_PATH]; DWORD n = GetModuleFileNameW(m, w, MAX_PATH);
        char a[MAX_PATH]; size_t i;
        if (n == 0 || n >= MAX_PATH) return;
        for (i = 0; i < n && i < sizeof(a) - 1; i++) a[i] = (char)w[i];
        a[i] = 0;
        _snprintf(out, cap, "%s+0x%x", strrchr(a, '\\') ? strrchr(a, '\\') + 1 : a,
                  (unsigned)((char *)addr - (char *)m));
    } else
        _snprintf(out, cap, "outside");
}

static void cpp_throw_name(struct _EXCEPTION_RECORD *er, char *out, size_t cap)
{
    ULONG_PTR ti, td;
    out[0] = 0;
    if (er->NumberParameters < 4) return;
    ti = er->ExceptionInformation[3];
    if (!readable((void *)ti)) return;
    td = *(ULONG_PTR *)(ti + 8);
    if (!readable((void *)td) || !readable((void *)(td + 8))) return;
    strncpy(out, (const char *)(td + 8), cap - 1);
    out[cap - 1] = 0;
}

static LONG WINAPI veh(struct _EXCEPTION_POINTERS *ep)
{
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    char rip[160], tgt[160], nm[256];
    mod_of((void *)ep->ExceptionRecord->ExceptionAddress, rip, sizeof(rip));
    if (code == 0xE06D7363) {
        cpp_throw_name(ep->ExceptionRecord, nm, sizeof(nm));
        printf("CPPTHROW case=%lu type=%s rip=%s p1=%I64x p3=%I64x\n", g_which,
               nm[0] ? nm : "?", rip,
               (unsigned __int64)ep->ExceptionRecord->ExceptionInformation[1],
               (unsigned __int64)ep->ExceptionRecord->ExceptionInformation[3]);
        fflush(stdout);
        g_throws++;
        return EXCEPTION_CONTINUE_SEARCH;
    }
    tgt[0] = 0;
    if (code == EXCEPTION_ACCESS_VIOLATION && ep->ExceptionRecord->NumberParameters >= 2)
        mod_of((void *)ep->ExceptionRecord->ExceptionInformation[1], tgt, sizeof(tgt));
    printf("FAULT case=%lu code=%08x rw=%lu addr=0x%I64x rip=%s tgt=%s\n",
           g_which, code,
           code == EXCEPTION_ACCESS_VIOLATION && ep->ExceptionRecord->NumberParameters >= 2
               ? (unsigned long)ep->ExceptionRecord->ExceptionInformation[0] : 0xFFFFFFFFu,
           (unsigned __int64)(uintptr_t)ep->ExceptionRecord->ExceptionAddress, rip, tgt);
    fflush(stdout);
    g_faults++;
    return EXCEPTION_CONTINUE_SEARCH;
}

static void *load_file(const char *p, unsigned long *cb)
{
    HANDLE h = CreateFileA(p, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, 0, NULL);
    DWORD n = 0; BYTE *tmp = NULL;
    *cb = 0;
    if (h == INVALID_HANDLE_VALUE) return NULL;
    n = GetFileSize(h, NULL);
    if (n != 0 && n != 0xFFFFFFFF) {
        tmp = (BYTE *)malloc(n);
        if (!tmp || !ReadFile(h, tmp, n, &n, NULL) || !n) { free(tmp); tmp = NULL; }
    }
    CloseHandle(h);
    if (tmp) *cb = n;
    return tmp;
}

static int call_bytes(const void *blob, unsigned long cb, int kind, int abi, void **out)
{
    void *stm, *o = NULL, *slot[2];
    int f0 = g_faults;
    *out = NULL;
    if (!g_fp[kind]) return 0;
    stm = pMemStream((const unsigned char *)blob, cb);
    if (!stm) return 0;
    memset(slot, 0, sizeof(slot));
    __try {
        if (abi == 1) o = ((PFN1)g_fp[kind])(stm);
        else { ((PFN2)g_fp[kind])(slot, stm); o = slot[0] ? slot[0] : slot[1]; }
    } __except (GetExceptionCode() == 0xE06D7363 ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_EXECUTE_HANDLER) {
        o = NULL;
    }
    irelease(stm);
    *out = o;
    return g_faults - f0;
}

static void try_inits(void)
{
    void *getC = (void *)GetProcAddress(g_gfx, NM_GETCFG);
    void *iniC = (void *)GetProcAddress(g_gfx, NM_CFGINIT);
    void *osp  = (void *)GetProcAddress(g_gfx, NM_OSP);
    void *cfg = NULL;
    int (*pInit)(void) = (int (*)(void))GetProcAddress(g_gfx, NM_INIT);
    printf("SYM cfg=%p getcfg=%p osp=%p\n", (void *)pInit, getC, osp);
    __try { if (osp) ((void (*)(void))osp)(); } __except (EXCEPTION_EXECUTE_HANDLER) { printf("OSP_SEH\n"); }
    __try { if (getC) cfg = ((void *(*)(void))getC)(); } __except (EXCEPTION_EXECUTE_HANDLER) { printf("GETCFG_SEH\n"); }
    printf("cfg=%p\n", cfg);
    __try { if (iniC && cfg) ((void (*)(void *))iniC)(cfg); } __except (EXCEPTION_EXECUTE_HANDLER) { printf("CFGINIT_SEH\n"); }
    printf("FGfxInitialized=%d\n", pInit ? pInit() : -1);
    fflush(stdout);
}

int main(int argc, char **argv)
{
    const char *g, *m, *mode, *arg;
    char path[MAX_PATH];
    int kind = 0, abi = 2, start = 0, cap = 100000, i;

    g = getenv("GFXDir");
    m = getenv("MSODir");
    if (!g) g = "C:\\Program Files\\Microsoft Office\\root\\Office16";
    if (!m) m = "C:\\Program Files\\Microsoft Office\\root\\vfs\\ProgramFilesCommonX64\\Microsoft Shared\\OFFICE16";
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR);
    AddDllDirectory(g);
    AddDllDirectory(m);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    AddVectoredExceptionHandler(1, veh);

    _snprintf(path, sizeof(path), "%s\\mso.dll", m);
    printf("PRELOAD mso=%p err=%lu\n",
           (void *)LoadLibraryExA(path, NULL, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR),
           (unsigned long)GetLastError());
    _snprintf(path, sizeof(path), "%s\\GFX.dll", g);
    g_gfx = LoadLibraryExA(path, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    printf("LOAD gfx=%p err=%lu\n", (void *)g_gfx, (unsigned long)(g_gfx ? 0 : GetLastError()));
    if (!g_gfx) return 2;
    g_fp[0] = (void *)GetProcAddress(g_gfx, NM_META);
    g_fp[1] = (void *)GetProcAddress(g_gfx, NM_IMAGE);
    printf("E_meta=%p E_img=%p\n", g_fp[0], g_fp[1]);
    pMemStream = (MEMSTREAM_FN)(void *)GetProcAddress(LoadLibraryA("shlwapi.dll"), "SHCreateMemStream");
    if (!pMemStream) { printf("no SHCreateMemStream\n"); return 5; }

    mode = argc > 1 ? argv[1] : "init";
    arg  = argc > 2 ? argv[2] : NULL;

    if (strcmp(mode, "selftest") == 0) {
        unsigned char *p = (unsigned char *)malloc(64);
        printf("SELFTEST ptr=%p\n", (void *)p); fflush(stdout);
        __try { p[64] = 0x41; } __except (EXCEPTION_EXECUTE_HANDLER) { printf("SELFTEST CAUGHT\n"); }
        printf("SELFTEST tail faults=%d (armed page heap must make this >=1)\n", g_faults);
        fflush(stdout);
        p[0] = 0x42;
        return 0;
    }
    if (strcmp(mode, "init") == 0) { try_inits(); return 0; }

    if (strcmp(mode, "probe") == 0) {
        unsigned long cb = 0; void *b; void *o = NULL;
        try_inits();
        if (!arg || !(b = load_file(arg, &cb))) { printf("no blob\n"); return 3; }
        for (kind = 0; kind < 2; kind++)
            for (abi = 1; abi <= 2; abi++) {
                int nf = call_bytes(b, cb, kind, abi, &o);
                printf("PROBE file=%s kind=%d abi=%d len=%lu obj=%p ok=%d newfaults=%d throws=%d\n",
                       arg, kind, abi, cb, o, obj_ok(o), nf, g_throws);
                fflush(stdout);
                irelease(o);
            }
        free(b);
        return 0;
    }

    if (strcmp(mode, "sweep") == 0) {
        WIN32_FIND_DATAA fd; HANDLE hf; int n = 0, okn = 0, hit = 0;
        char pat[MAX_PATH], full[MAX_PATH];
        const char *kd;
        if (!arg) { printf("usage: sweep <dir> <meta|img> <abi> <start> <cap>\n"); return 3; }
        kd = argc > 3 ? argv[3] : "meta";
        kind = (kd[0] == 'i') ? 1 : 0;
        abi  = argc > 4 ? atoi(argv[4]) : 2;
        start = argc > 5 ? atoi(argv[5]) : 0;
        cap  = argc > 6 ? atoi(argv[6]) : 2000;
        _snprintf(pat, sizeof(pat), "%s\\*.emf", arg);
        if (kd[0] == 'p') { strcpy(pat + strlen(pat) - 4, "*.png"); }
        hf = FindFirstFileA(pat, &fd);
        if (hf == INVALID_HANDLE_VALUE) { printf("nofiles dir=%s\n", arg); return 3; }
        do {
            unsigned long cb = 0; void *b; void *o = NULL; int nf;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            if (n++ < start) continue;
            if (n - start > cap) break;
            _snprintf(full, sizeof(full), "%s\\%s", arg, fd.cFileName);
            b = load_file(full, &cb);
            if (!b) continue;
            nf = call_bytes(b, cb, kind, abi, &o);
            if (obj_ok(o)) okn++;
            printf("PROG idx=%d file=%s ok=%d nf=%d\n", n, fd.cFileName, obj_ok(o) ? 1 : 0, nf);
            fflush(stdout);
            if (nf) {
                hit++;
                printf("HIT file=%s len=%lu\n", full, cb);
                fflush(stdout);
            }
            irelease(o);
            free(b);
        } while (FindNextFileA(hf, &fd));
        FindClose(hf);
        printf("SUMMARY kind=%s abi=%d start=%d cases=%d ok=%d hits=%d throws=%d\n",
               kd, abi, start, n - start, okn, hit, g_throws);
        fflush(stdout);
        return 0;
    }
    printf("usage: gfxprobe3 [selftest|init|probe <file>|sweep <dir> <meta|img> <abi> <start> <cap>]\n");
    (void)i;
    return 4;
}
