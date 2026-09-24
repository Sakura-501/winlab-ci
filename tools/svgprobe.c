/* svgprobe.c -- in-process rig for MSOSVG.DLL (Office's own SVG parser, loaded on demand by
 * mso's SVGBlip::GetSVGImage -> CreateSVGImage1Proxy(outObj, IStream*)).
 *
 * Run under full page heap on this exe (IFEO GlobalFlag=0x02000000), so a one-byte tail write or a
 * use-after-free faults instead of silently corrupting the next chunk. The VEH records the fault
 * address, the module owning the faulting RIP, and whether the accessed address sits just past a
 * live allocation, then swallows the exception so the case still prints its row.
 *
 *   svgprobe_x64 selftest            deliberately writes 1 byte past a malloc'ed block; the row
 *                                    must read OOBO=1 or the whole campaign is instrument-blind
 *   svgprobe_x64 init               load Office dirs + msosvg.dll, report the proxy entry points
 *   svgprobe_x64 one <file.svg>     parse one payload (and optionally walk the object vtable)
 *   svgprobe_x64 one <file.svg> v   additionally call the object's vtable slots
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* objidlbase.h (pulled in by windows.h) already declares STATSTG and LPSTREAM; redeclaring
 * them is a C2011/C2371 on 10.0.26100 headers (run 36062072487). */

typedef LPSTREAM (WINAPI *PSCREATEMEMSTREAM)(const void *, DWORD);

/* CreateSVGImage1Proxy(void **outObj, IStream *src) per mso 0x180b74de0 */
typedef HRESULT (WINAPI *PCREATESVG)(void **, LPSTREAM);

static PSCREATEMEMSTREAM pSHCreateMemStream;
static HMODULE g_svg;
static FARPROC g_proxy[2];
static const char *g_proxyName[2] = { "CreateSVGImage1Proxy",
                                      "ISVGImageFactoryCreateSVGImage1Proxy" };
static int g_faults, g_throws;
static DWORD g_code, g_which;
static char g_ripMod[260], g_addrOwner[260];
static void *g_rip, *g_addr;
static int g_writedir;
static int g_walk;

static LONG CALLBACK veh(struct _EXCEPTION_POINTERS *ep)
{
    DWORD c = ep->ExceptionRecord->ExceptionCode;
    if (c == (DWORD)0xE06D7363) { g_throws++; return EXCEPTION_EXECUTE_HANDLER; }
    if (c == EXCEPTION_ACCESS_VIOLATION) {
        g_faults++;
        g_code = c;
        g_rip = ep->ExceptionRecord->ExceptionAddress;
        g_writedir = (ep->ExceptionRecord->NumberParameters > 0) &&
                     (ep->ExceptionRecord->ExceptionInformation[0] == 1);
        g_addr = (void *)ep->ExceptionRecord->ExceptionInformation[1];
        return EXCEPTION_EXECUTE_HANDLER;
    }
    if (c == EXCEPTION_IN_PAGE_ERROR || c == EXCEPTION_DATATYPE_MISALIGNMENT ||
        c == EXCEPTION_ILLEGAL_INSTRUCTION || c == EXCEPTION_STACK_OVERFLOW ||
        c == (DWORD)0xC0000409) {
        g_faults++;
        g_code = c;
        g_rip = ep->ExceptionRecord->ExceptionAddress;
        g_addr = (ep->ExceptionRecord->NumberParameters > 1)
                     ? (void *)ep->ExceptionRecord->ExceptionInformation[1] : NULL;
        g_writedir = (ep->ExceptionRecord->NumberParameters > 0) &&
                     (ep->ExceptionRecord->ExceptionInformation[0] == 1);
        return EXCEPTION_EXECUTE_HANDLER;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void mod_of(void *addr, char *out, size_t cap)
{
    MEMORY_BASIC_INFORMATION mi;
    out[0] = 0;
    if (!addr) { snprintf(out, cap, "-"); return; }
    if (VirtualQuery(addr, &mi, sizeof(mi))) {
        HMODULE m = (HMODULE)mi.AllocationBase;
        wchar_t w[MAX_PATH];
        if (m && GetModuleFileNameW(m, w, MAX_PATH)) {
            int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)cap - 1, NULL, NULL);
            if (n > 0) {
                char *base = strrchr(out, '\\');
                if (base) memmove(out, base + 1, strlen(base + 1) + 1);
                return;
            }
        }
        snprintf(out, cap, "alloc@0x%p", mi.AllocationBase);
        return;
    }
    snprintf(out, cap, "unmapped");
}

static int readable(const void *p)
{
    MEMORY_BASIC_INFORMATION mi;
    if (!p) return 0;
    if (!VirtualQuery((LPCVOID)p, &mi, sizeof(mi))) return 0;
    if (mi.State != MEM_COMMIT) return 0;
    switch (mi.Protect & 0xFF) {
    case PAGE_READONLY: case PAGE_READWRITE: case PAGE_WRITECOPY: case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE: case PAGE_EXECUTE_WRITECOPY:
        return (mi.Protect & PAGE_GUARD) ? 0 : 1;
    default:
        return 0;
    }
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

/* Force the parser past a lazy top-level read: call the object's own vtable slots. Slots that are
 * not functions fault on the bad-code path, which the VEH turns into a counted row. */
static void walk(void *o)
{
    void *vt;
    int i;
    if (!obj_ok(o)) return;
    vt = *(void **)o;
    for (i = 0; i < 12; i++) {
        void *fn = ((void **)vt)[i];
        if (!readable(fn)) continue;
        __try {
            ((HRESULT (*)(void *))fn)(o);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            g_faults++;
            g_code = (DWORD)GetExceptionCode();
        }
        if (g_faults) return;
    }
}

static int load_dir(const wchar_t *dir)
{
    if (AddDllDirectory(dir)) return 1;
    return 0;
}

static int office_init(void)
{
    wchar_t root[MAX_PATH], d1[MAX_PATH], d2[MAX_PATH];
    HMODULE mso, c20, c40;
    DWORD e;
    if (!SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS))
        printf("SetDefaultDllDirectories err=%lu\n", GetLastError());
    if (!GetModuleFileNameW(NULL, root, MAX_PATH)) { printf("no exepath err=%lu\n", GetLastError()); return 0; }
    {
        wchar_t *s = wcsrchr(root, L'\\');
        if (s) *s = 0;
        s = wcsrchr(root, L'\\');
        if (s) *s = 0;              /* strip ..\svglab -> keep Office root */
    }
    swprintf(d1, MAX_PATH, L"%s\\Office16", root);
    swprintf(d2, MAX_PATH,
             L"%s\\vfs\\ProgramFilesCommonX64\\Microsoft Shared\\OFFICE16", root);
    printf("dir1=%S\n", d1);
    printf("dir2=%S\n", d2);
    load_dir(d1); load_dir(d2);
    mso = LoadLibraryExW(d2, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (mso) printf("mso=ok\n");
    {
        wchar_t p[MAX_PATH];
        swprintf(p, MAX_PATH, L"%s\\Mso20Win32Client.dll", d1);
        c20 = LoadLibraryExW(p, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
        printf("Mso20Win32Client=%s err=%lu\n", c20 ? "ok" : "FAIL", c20 ? 0 : GetLastError());
        swprintf(p, MAX_PATH, L"%s\\mso40uiWin32Client.dll", d1);
        c40 = LoadLibraryExW(p, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
        printf("mso40uiWin32Client=%s err=%lu\n", c40 ? "ok" : "FAIL", c40 ? 0 : GetLastError());
        swprintf(p, MAX_PATH, L"%s\\msosvg.dll", d1);
        g_svg = LoadLibraryExW(p, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
        e = GetLastError();
        printf("msosvg=%s err=%lu\n", g_svg ? "ok" : "FAIL", e);
        if (!g_svg) {
            swprintf(p, MAX_PATH, L"%s\\MSOSVG.DLL", d1);
            g_svg = LoadLibraryExW(p, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
            printf("msosvg2=%s err=%lu\n", g_svg ? "ok" : "FAIL", GetLastError());
        }
    }
    if (!g_svg) return 0;
    {
        wchar_t wv[MAX_PATH]; void *vp;
        GetModuleFileNameW(g_svg, wv, MAX_PATH);
        vp = GetProcAddress(g_svg, "CreateSVGImage1Proxy");
        printf("svgpath=%S\nproxy_a=0x%p\n", wv, vp);
        g_proxy[0] = (FARPROC)vp;
        g_proxy[1] = GetProcAddress(g_svg, g_proxyName[1]);
        printf("proxy_b=%p\n", (void *)g_proxy[1]);
    }
    return 1;
}

static unsigned char *slurp(const char *path, DWORD *len)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    unsigned char *b;
    DWORD sz, rd;
    if (h == INVALID_HANDLE_VALUE) { printf("openfail err=%lu\n", GetLastError()); return NULL; }
    sz = GetFileSize(h, NULL);
    b = (unsigned char *)malloc(sz ? sz : 1);
    if (!ReadFile(h, b, sz, &rd, NULL) || rd != sz) { CloseHandle(h); free(b); return NULL; }
    CloseHandle(h);
    *len = sz;
    return b;
}

static int run_one(const char *path, int doWalk)
{
    DWORD len = 0;
    unsigned char *b = slurp(path, &len);
    LPSTREAM stm;
    void *obj = NULL;
    HRESULT hr = (HRESULT)0xE0FFFF01;
    int ok = 0;
    if (!b) { printf("READFAIL file=%s\n", path); return 2; }
    stm = pSHCreateMemStream(b, len);
    if (!stm) { printf("MEMSTREAMFAIL file=%s len=%lu\n", path, len); free(b); return 3; }
    g_faults = 0; g_throws = 0;
    __try {
        if (g_proxy[0]) hr = ((PCREATESVG)g_proxy[0])(&obj, stm);
        else if (g_proxy[1]) hr = ((PCREATESVG)g_proxy[1])(&obj, stm);
        else hr = (HRESULT)0xE0FFFF02;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_faults++;
        g_code = (DWORD)GetExceptionCode();
    }
    ok = obj_ok(obj);
    if (doWalk && ok) walk(obj);
    mod_of(g_rip, g_ripMod, sizeof(g_ripMod));
    mod_of(g_addr, g_addrOwner, sizeof(g_addrOwner));
    printf("ROW file=%s len=%lu hr=0x%08X obj=%p objok=%d faults=%d code=0x%08X dir=%s "
           "rip=%p[%s] addr=%p[%s] throws=%d\n",
           path, len, (unsigned)hr, obj, ok, g_faults, g_code,
           g_writedir ? "WRITE" : "READ", g_rip, g_ripMod, g_addr, g_addrOwner, g_throws);
    fflush(stdout);
    free(b);
    return g_faults ? 1 : 0;
}

int main(int argc, char **argv)
{
    HMODULE sh;
    SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)veh);
    AddVectoredExceptionHandler(1, veh);
    setvbuf(stdout, NULL, _IONBF, 0);
    sh = LoadLibraryA("shlwapi.dll");
    if (!sh) { printf("shlwapi FAIL err=%lu\n", GetLastError()); return 9; }
    pSHCreateMemStream = (PSCREATEMEMSTREAM)GetProcAddress(sh, "SHCreateMemStream");
    printf("SHCreateMemStream=%p\n", (void *)pSHCreateMemStream);
    if (argc < 2) { printf("usage: svgprobe selftest|init|one <file> [v]\n"); return 8; }

    if (!strcmp(argv[1], "selftest")) {
        volatile char *p = (volatile char *)malloc(0x1000);
        int before = g_faults;
        printf("SELFTEST malloc=%p pagesize=%lu\n", (void *)p, (DWORD)64);
        __try {
            p[0x1000] = 1;                  /* one byte past a 4096-byte request */
            printf("SELFTEST tailwrite survived (expected under full page heap to fault)\n");
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            g_faults++;
            g_code = (DWORD)GetExceptionCode();
        }
        printf("SELFTEST ooobo=%d code=0x%08X delta=%d\n", g_faults > before ? 1 : 0, g_code,
               g_faults - before);
        fflush(stdout);
        return g_faults > before ? 0 : 4;   /* nonzero => instrument blind */
    }

    if (!strcmp(argv[1], "init")) {
        if (!office_init()) { printf("INITFAIL\n"); return 5; }
        printf("INIT ok\n");
        return 0;
    }

    if (!strcmp(argv[1], "one")) {
        if (argc < 3) { printf("need a file\n"); return 8; }
        if (!office_init()) { printf("INITFAIL\n"); return 5; }
        if (!pSHCreateMemStream) { printf("NOMEMSTREAM\n"); return 6; }
        return run_one(argv[2], argc > 3 && !strcmp(argv[3], "v"));
    }
    printf("unknown mode\n");
    return 8;
}
