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
typedef HRESULT (STDAPICALLTYPE *PFN_PARSE_ADDR)(ULONG, ULONG, const char *, void *);
typedef HRESULT (STDAPICALLTYPE *PFN_OPEN_TNEF_MSG)(void *, IStream *, void **, LPCSTR, ULONG, void *, void *);
typedef HRESULT (STDAPICALLTYPE *PFN_OPENMSGSESS)(void *, ULONG, void **);
typedef HRESULT (STDAPICALLTYPE *PFN_OPENMSGONI)(void *, void *, void *, void *, void *, void *, void *, void *, ULONG, ULONG, void **);
typedef HRESULT (STDAPICALLTYPE *PFN_ALLOCBUF)(ULONG, void **);
typedef HRESULT (STDAPICALLTYPE *PFN_ALLOCMORE)(ULONG, void *, void **);
typedef void (STDAPICALLTYPE *PFN_FREEBUF)(void *);
typedef HRESULT (STDAPICALLTYPE *PFN_MAPIINIT)(void *);
typedef HRESULT (STDAPICALLTYPE *PFN_MAPIUNINIT)(void);
typedef ULONG (STDAPICALLTYPE *PFN_RELEASE)(void *);

static PFN_WRAP       g_pWrap = nullptr;
static PFN_WRAP       g_pWrapEx = nullptr;
static HMODULE        g_hOlm = nullptr;
static char           g_modname[260] = {0};
static uintptr_t      g_modbase = 0;
static volatile LONG  g_in_handler = 0;
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
        IMalloc *pMalloc2 = nullptr; CoGetMalloc(MEMCTX_TASK, &pMalloc2);
        void *pSession2 = nullptr;
        pSess2(nullptr, 0, &pSession2);
        unsigned long cnt = 0, opened2 = 0, syncs = 0, ups = 0;
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
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
        while (off + 1 < fsz && n < 200000) {
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
