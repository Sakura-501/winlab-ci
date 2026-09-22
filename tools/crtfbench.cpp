// crtfbench.cpp - in-process driver for OLMAPI32's MS-OXRTFCP 'LZFu' decompressor
// Usage: crtfbench <blob|-> [flags-hex] [readchunk] [mode]
//   mode 0 = Wrap + read to EOF            (default)
//   mode 1 = Wrap + seek pattern + read
//   mode 2 = Wrap + Stat + Clone + read
// Prints: WRAP rc= / READS n got= / SEEK rc= / and on AV: AV code rw= target= module+rva
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <objbase.h>

typedef HRESULT (STDAPICALLTYPE *PFN_WRAP)(IStream *, ULONG, IStream **);
typedef HRESULT (STDAPICALLTYPE *PFN_OPEN_TNEF)(IStream *, void **, LPCSTR, ULONG, void *, void *, void *);
typedef HRESULT (STDAPICALLTYPE *PFN_GET_TNEF_STM)(void *, IStream **);
typedef HRESULT (STDAPICALLTYPE *PFN_RTFSYNC)(void *, ULONG, int *);
typedef HRESULT (STDAPICALLTYPE *PFN_OPENMSGSESS)(void *, ULONG, void **);
typedef HRESULT (STDAPICALLTYPE *PFN_OPENMSGONI)(void *, void *, void *, void *, void *, void *, void *, void *, ULONG, ULONG, void **);
typedef HRESULT (STDAPICALLTYPE *PFN_ALLOCBUF)(ULONG, void **);
typedef HRESULT (STDAPICALLTYPE *PFN_ALLOCMORE)(ULONG, void *, void **);
typedef void (STDAPICALLTYPE *PFN_FREEBUF)(void *);
typedef HRESULT (STDAPICALLTYPE *PFN_MAPIINIT)(void *);
typedef HRESULT (STDAPICALLTYPE *PFN_MAPIUNINIT)(void);

static PFN_WRAP       g_pWrap = nullptr;
static PFN_WRAP       g_pWrapEx = nullptr;
static HMODULE        g_hOlm = nullptr;
static char           g_modname[260] = {0};
static uintptr_t      g_modbase = 0;
static volatile LONG  g_in_handler = 0;

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
    if (code == EXCEPTION_ACCESS_VIOLATION) {
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


static DWORD WINAPI Watchdog(LPVOID arg)
{
    DWORD ms = (DWORD)(ULONG_PTR)arg;
    Sleep(ms);
    printf("WATCHDOG_FIRE after=%lu ms\n", ms); fflush(stdout);
    TerminateProcess(GetCurrentProcess(), 0x48414E47);
    return 0;
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
    if (pInit) { HRESULT hr = pInit(nullptr); printf("MAPIInitialize hr=%08x\n", (unsigned)hr); }

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
    size_t cb = 0; BYTE *buf = nullptr;
    if (strcmp(argv[1], "-") != 0) {
        buf = LoadBlob(argv[1], &cb);
        if (!buf) { printf("READFAIL %s\n", argv[1]); return 5; }
    } else {
        cb = (size_t) fread(calloc(1, 1 << 20), 1, 1 << 20, stdin);
        buf = (BYTE *)realloc(buf, cb ? cb : 1);
    }
    ULONG flags = (argc > 2) ? (ULONG)strtoul(argv[2], nullptr, 16) : 0;
    ULONG chunk = (argc > 3) ? (ULONG)strtoul(argv[3], nullptr, 10) : 0x100;
    int mode = (argc > 4) ? atoi(argv[4]) : 0;
    printf("blob=%zu flags=%x chunk=%u mode=%d\n", cb, flags, chunk, mode);

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
