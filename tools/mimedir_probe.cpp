// mimedir_probe.cpp - in-proc driver for Office's MIME/iCal/vCal converter (MIMEDIR.DLL, x64).
// usage: mimedir_probe <mode> [file|dir] [icallvl]
//   0 = print class/interface guids + candidate export presence
//   2 = IMDCvt_iCal slot 4 ImportFromIcalStream        (iCal text -> MAPI item)
//   3 = IMDCvt_iCal slot 5 IcalStreamToMessage
//   4 = IMDCvt_iCal slot 3 StatIcalStream
//   5 = IMDCvt_iCal slot 10 IfbStreamToFreeBusy        (.ifb free/busy)
//   6 = IMDCvt_vCal  slot 4/5 (same-shape vCal import)
//   7 = dump the created object's vtable slots 0..14 (module+RVA each)
//   8 = sweep a directory: fresh instance per file, chosen slot, print one line per case
#include <windows.h>
#include <objbase.h>
#include <objidl.h>
#include <psapi.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static HMODULE g_mods[300]; static char g_names[300][MAX_PATH]; static int g_nmod = 0;
static void CollectMods(void) {
  DWORD need = 0;
  if (EnumProcessModules(GetCurrentProcess(), g_mods, sizeof(g_mods), &need)) {
    g_nmod = (int)(need / sizeof(HMODULE));
    for (int i = 0; i < g_nmod; i++)
      if (!GetModuleFileNameA(g_mods[i], g_names[i], MAX_PATH)) strcpy_s(g_names[i], MAX_PATH, "?");
  }
}
static LONG CALLBACK Veh(struct _EXCEPTION_POINTERS *ep) {
  DWORD_PTR a = (DWORD_PTR)ep->ExceptionRecord->ExceptionAddress;
  DWORD c = ep->ExceptionRecord->ExceptionCode;
  if (c == 0xe06d7363 || c == 0xe0000002 || c == 0x40010006) return EXCEPTION_CONTINUE_SEARCH;
  CollectMods();
  for (int i = 0; i < g_nmod; i++) {
    MODULEINFO mi;
    if (GetModuleInformation(GetCurrentProcess(), g_mods[i], &mi, sizeof(mi)) &&
        a >= (DWORD_PTR)mi.lpBaseOfDll && a < (DWORD_PTR)mi.lpBaseOfDll + mi.SizeOfImage) {
      char *b = strrchr(g_names[i], '\\');
      printf("!!!AV code=0x%08x addr=0x%p inside %s + 0x%x\n", c, (void *)a, b ? b + 1 : g_names[i],
             (unsigned)(a - (DWORD_PTR)mi.lpBaseOfDll));
      fflush(stdout); return EXCEPTION_CONTINUE_SEARCH;
    }
  }
  printf("!!!AV code=0x%08x addr=0x%p inside <unknown>\n", c, (void *)a);
  fflush(stdout);
  return EXCEPTION_CONTINUE_SEARCH;
}

// {0006F090-...} {000672A7-...} iCal ; {0006F08F-...} {00067297-...} vCal
static const IID g_iidzero = { 0, 0, 0, { 0, 0, 0, 0, 0, 0, 0, 0 } };
static const CLSID CLSID_iCal = { 0x0006F090, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
static const IID   IID_iCal   = { 0x000672A7, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
static const CLSID CLSID_vCal = { 0x0006F08F, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
static const IID   IID_vCal   = { 0x00067297, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
static const CLSID CLSID_Parser = { 0x0006F082, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
static const IID   IID_Parse = { 0x00067294, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
static const IID   IID_ParseNotify = { 0x00067296, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
static const IID   IID_Item = { 0x00067293, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
static const IID   IID_Schema = { 0x00067291, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
static const CLSID CLSID_Item = { 0x0006F081, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
static const CLSID CLSID_Schema = { 0x0006F084, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
static const CLSID CLSID_MapiCvt = { 0x0006F085, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };

typedef SCODE (*PFN2)(void *, IStream *, void *, void *, void *, void *, void *, ULONG, int, int *);
typedef SCODE (*PFN3)(void *, IStream *, void *, void *, void *, void *, int *, void *, void *, int, int *, void *, void *, ULONG *);
typedef SCODE (*PFN4)(void *, IStream *, ULONG, void *, int, void *);
typedef SCODE (*PFN5)(void *, IStream *, void **, ULONG *, void *, void *);

static void **VT(void *obj) { return *(void ***)obj; }

static IStream *FileToStream(const char *path) {
  WCHAR wp[MAX_PATH * 2];
  MultiByteToWideChar(CP_ACP, 0, path, -1, wp, (int)(sizeof(wp) / sizeof(wp[0])));
  IStream *stm = 0;
  if (FAILED(SHCreateStreamOnFileEx(wp, STGM_READ | STGM_SHARE_EXCLUSIVE, 0, FALSE, 0, &stm)) || !stm) {
    printf("stream_fail path=%s\n", path); return 0;
  }
  return stm;
}

typedef SCODE (*PFN_GCO)(const CLSID &, const IID &, void **);
static PFN_GCO g_gco = 0;
static char g_dllpath[MAX_PATH] = "";
static void ResolveDll(void) {
  const char *roots[] = { "C:\\Program Files\\Microsoft Office\\root\\Office16\\",
                          "C:\\Program Files (x86)\\Microsoft Office\\root\\Office16\\", 0 };
  char buf[4096]; DWORD n = sizeof(buf) - 1;
  HKEY k;
  if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Office\\ClickToRun", 0, KEY_READ | KEY_WOW64_64KEY, &k) == ERROR_SUCCESS) {
    DWORD t = 0;
    if (RegQueryValueExA(k, "InstallationPath", 0, &t, (LPBYTE)buf, &n) == ERROR_SUCCESS) {
      size_t l = strlen(buf);
      if (l && buf[l - 1] != '\\') { buf[l] = '\\'; buf[l + 1] = 0; }
      RegCloseKey(k);
      _snprintf(g_dllpath, sizeof(g_dllpath), "%sMIMEDIR.DLL", buf);
      goto tryall;
    }
    RegCloseKey(k);
  }
  for (int i = 0; roots[i]; i++) { _snprintf(g_dllpath, sizeof(g_dllpath), "%sMIMEDIR.DLL", roots[i]);
    if (GetFileAttributesA(g_dllpath) != INVALID_FILE_ATTRIBUTES) break; }
tryall:
  if (GetFileAttributesA(g_dllpath) == INVALID_FILE_ATTRIBUTES) { strcpy(g_dllpath, "MIMEDIR.DLL"); }
  HMODULE h = LoadLibraryExA(g_dllpath, 0, LOAD_WITH_ALTERED_SEARCH_PATH);
  if (h) g_gco = (PFN_GCO)GetProcAddress(h, "DllGetClassObject");
  printf("dll=%s gcobj=0x%p ", strrchr(g_dllpath, '\\') ? strrchr(g_dllpath, '\\') + 1 : g_dllpath, (void *)g_gco);
}

struct Outer { void **vt; long refs; };
static HRESULT STDMETHODCALLTYPE OQ(void *t, const IID &riid, void **pp) {
  if (!pp) return E_POINTER;
  if (riid == IID_IUnknown || IsEqualIID(riid, *(IID *)&g_iidzero)) { *pp = t; return S_OK; }
  *pp = 0; return 0x80004002L;   // E_NOINTERFACE
}
static HRESULT STDMETHODCALLTYPE OQANY(void *t, const IID &, void **pp) { if (!pp) return E_POINTER; *pp = t; return S_OK; }
static ULONG STDMETHODCALLTYPE OA(void *t) { return 1; }
static ULONG STDMETHODCALLTYPE OR_(void *t) { return 1; }
static void *g_vt[4] = { (void *)OQANY, (void *)OA, (void *)OR_, 0 };
static Outer g_outer = { g_vt, 1 };

static HRESULT STDMETHODCALLTYPE OQN(void *t, const IID &riid, void **pp) {
  if (!pp) return E_POINTER;
  if (riid == IID_IUnknown || riid == IID_ParseNotify) { *pp = t; return S_OK; }
  *pp = 0; return 0x80004002L;
}
static HRESULT STDMETHODCALLTYPE STUB(void *t) { return 0x80004001L; }
static HRESULT STDMETHODCALLTYPE OK(void *t) { return S_OK; }
static long g_calls[32];
#define NFN(i) static HRESULT STDMETHODCALLTYPE N##i(void *t) { g_calls[i]++; return S_OK; }
NFN(3) NFN(4) NFN(5) NFN(6) NFN(7) NFN(8) NFN(9) NFN(10)
NFN(11) NFN(12) NFN(13) NFN(14) NFN(15) NFN(16) NFN(17) NFN(18)
static void *g_nvt[26] = { (void *)OQN, (void *)OA, (void *)OR_,
  (void *)N3,(void *)N4,(void *)N5,(void *)N6,(void *)N7,(void *)N8,(void *)N9,(void *)N10,
  (void *)N11,(void *)N12,(void *)N13,(void *)N14,(void *)N15,(void *)N16,(void *)N17,(void *)N18,
  (void *)OK,(void *)OK,(void *)OK,(void *)OK,(void *)OK,(void *)OK };
static Outer g_notify = { g_nvt, 1 };

static void *NewObj(const CLSID &cls, const IID &iid, SCODE *prc) {
  void *o = 0;
  if (!g_gco) { *prc = E_FAIL; return 0; }
  IClassFactory *cf = 0;
  SCODE h = g_gco(cls, IID_IClassFactory, (void **)&cf);
  if (h != S_OK || !cf) { *prc = h; return 0; }
  h = cf->CreateInstance((IUnknown *)&g_outer, iid, &o);
  if (h != S_OK) { h = cf->CreateInstance(0, iid, &o); }
  cf->Release();
  *prc = h;
  return h == S_OK ? o : 0;
}

static void RunSlot(void *o, IStream *stm, int slot) {
  void **vt = VT(o);
  SCODE r = 0;
  if (slot == 4) r = ((PFN2)vt[4])(o, stm, 0, 0, 0, 0, 0, 0, 0, 0);
  else if (slot == 5) r = ((PFN2)vt[5])(o, stm, 0, 0, 0, 0, 0, 0, 0, 0);
  else if (slot == 3) r = ((PFN4)vt[3])(o, stm, 0, 0, 0, 0);
  else if (slot == 10) { void *blk = 0; ULONG n = 0; void *t1, *t2;
    r = ((PFN5)vt[10])(o, stm, &blk, &n, &t1, &t2); printf(" fbblocks=%lu", n); }
  else r = ((PFN2)vt[slot])(o, stm, 0, 0, 0, 0, 0, 0, 0, 0);
  printf(" slot%d rc=0x%08x", slot, (unsigned)r);
}

static void ParseSweep(const char *dir, int usestub, int fresh) {
  SCODE rc0; void *o0 = NewObj(CLSID_Parser, IID_Parse, &rc0);
  if (!o0) { printf("parser create rc=0x%08x\n", (unsigned)rc0); return; }
  void **vt = VT(o0);
  static const char *exts[] = { "*.ics", "*.vcs", "*.vcf", "*.ifb", "*.mht", "*.eml", "*.txt", "*.htm", "*.xml", 0 };
  static char files[4000][MAX_PATH]; int nf = 0;
  for (int e = 0; exts[e] && nf < 4000; e++) {
    char pat[MAX_PATH]; _snprintf(pat, sizeof(pat), "%s\\%s", dir, exts[e]);
    WIN32_FIND_DATAA fd; HANDLE hf = FindFirstFileA(pat, &fd);
    if (hf == INVALID_HANDLE_VALUE) continue;
    do { if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
           _snprintf(files[nf++], MAX_PATH, "%s\\%s", dir, fd.cFileName); } while (nf < 4000 && FindNextFileA(hf, &fd));
    FindClose(hf);
  }
  printf("sweep dir=%s cases=%d stub=%d\n", dir, nf, usestub);
  int done = 0;
  for (int i = 0; i < nf; i++) {
    void *o = fresh ? NewObj(CLSID_Parser, IID_Parse, &rc0) : o0;
    if (!o) { printf("F%04d create rc=0x%08x\n", i, (unsigned)rc0); continue; }
    void **vti = fresh ? VT(o) : vt;
    IStream *stm = FileToStream(files[i]);
    if (!stm) { printf("F%04d skip %s\n", i, files[i]); continue; }
    ULONG t0 = GetTickCount();
    memset(g_calls, 0, sizeof(g_calls));
    printf("F%04d %s", i, strrchr(files[i], '\\') ? strrchr(files[i], '\\') + 1 : files[i]);
    SCODE h = ((SCODE(*)(void *, IStream *, void *, void *))vti[3])(o, stm, usestub ? &g_notify : 0, 0);
    long tot = 0; for (int q = 3; q < 19; q++) tot += g_calls[q];
    printf(" parse rc=0x%08x ms=%lu notify=%ld [3]=%ld [4]=%ld [5]=%ld [6]=%ld RESULT\n",
           (unsigned)h, (unsigned long)(GetTickCount() - t0), tot, g_calls[3], g_calls[4], g_calls[5], g_calls[6]);
    done++;
    stm->Release();
    if (fresh) ((HRESULT(*)(void *))vti[2])(o);
  }
  if (!fresh) ((HRESULT(*)(void *))vt[2])(o0);
  printf("DONE cases=%d done=%d\n", nf, done);
}

static void DumpVT(const char *tag, void *o) {
    if (!o) return;
    void **vt = VT(o);
    CollectMods();
    MODULEINFO mi;
    char *mod = (char *)"?"; unsigned rva = 0;
    for (int i = 0; i < g_nmod; i++) {
      if (GetModuleInformation(GetCurrentProcess(), g_mods[i], &mi, sizeof(mi)) &&
          (char *)vt[0] >= (char *)mi.lpBaseOfDll && (char *)vt[0] < (char *)mi.lpBaseOfDll + mi.SizeOfImage) {
        char *b = strrchr(g_names[i], '\\'); mod = b ? b + 1 : g_names[i];
        rva = (unsigned)((char *)vt[0] - (char *)mi.lpBaseOfDll);
        break;
      }
    }
    printf("VT %s mod=%s vtable_rva=0x%x\n", tag, mod, rva);
}

static void ProbeCls(const char *nm, const CLSID &cls) {
    IClassFactory *cf = 0;
    SCODE h = g_gco ? g_gco(cls, IID_IClassFactory, (void **)&cf) : E_FAIL;
    printf("CLS %s gc=0x%08x ", nm, (unsigned)h);
    if (h != S_OK || !cf) { printf("\n"); return; }
    const IID *cands[] = { &IID_IUnknown, &IID_iCal, &IID_vCal, &IID_Parse, &IID_Item, &IID_Schema, &IID_ParseNotify, 0 };
    const char *cn[] = { "IUnk", "IMDCvt_iCal", "IMDCvt_vCal", "IMimeDirParse", "IMimeDirItem", "IMimeDirSchema", "IParseNotify", 0 };
    for (int outer = 0; outer < 2; outer++) {
      for (int i = 0; cands[i]; i++) {
        void *o = 0;
        SCODE r = cf->CreateInstance(outer ? (IUnknown *)&g_outer : 0, *cands[i], &o);
        printf("[%s%s] rc=0x%08x ", cn[i], outer ? "/agg" : "", (unsigned)r);
        if (r == S_OK && o) { DumpVT(cn[i], o); ((HRESULT(*)(void *))VT(o)[2])(o); }
      }
    }
    cf->Release();
    printf("\n");
}

static void ConvSweep(const char *dir, int slot) {
  const char *names[] = { 0, 0, 0, "StatIcalStream", "ImportFromIcalStream", "IcalStreamToMessage", 0 };
  static char files[4000][MAX_PATH];
  static const char *exts[] = { "*.ics", "*.vcs", "*.vcf", "*.ifb", 0 };
  int nf = 0;
  for (int e = 0; exts[e]; e++) {
    char pat[MAX_PATH]; _snprintf(pat, sizeof(pat), "%s\\%s", dir, exts[e]);
    WIN32_FIND_DATAA fd; HANDLE hf = FindFirstFileA(pat, &fd);
    if (hf == INVALID_HANDLE_VALUE) continue;
    do { if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
           _snprintf(files[nf++], MAX_PATH, "%s\\%s", dir, fd.cFileName); } while (nf < 4000 && FindNextFileA(hf, &fd));
    FindClose(hf);
  }
  printf("conv sweep dir=%s cases=%d slot=%d(%s)\n", dir, nf, slot, slot < 7 && names[slot] ? names[slot] : "?");
  static char statbuf[4096];
  int done = 0;
  for (int i = 0; i < nf; i++) {
    IClassFactory *cf = 0;
    SCODE h = g_gco(CLSID_MapiCvt, IID_IClassFactory, (void **)&cf);
    if (h != S_OK) { printf("C%04d factory rc=0x%08x\n", i, (unsigned)h); return; }
    void *o = 0;
    h = cf->CreateInstance((IUnknown *)&g_outer, IID_iCal, &o);
    if (h != S_OK || !o) { h = cf->CreateInstance(0, IID_iCal, &o); }
    cf->Release();
    if (h != S_OK || !o) { printf("C%04d create_iid rc=0x%08x\n", i, (unsigned)h); continue; }
    void **vt = VT(o);
    IStream *stm = FileToStream(files[i]);
    if (!stm) { printf("C%04d skip\n", i); ((HRESULT(*)(void *))vt[2])(o); continue; }
    ULONG t0 = GetTickCount();
    printf("C%04d %s", i, strrchr(files[i], '\\') ? strrchr(files[i], '\\') + 1 : files[i]);
    SCODE r2 = 0;
    memset(statbuf, 0, sizeof(statbuf));
    if (slot == 3) r2 = ((SCODE(*)(void *, IStream *, ULONG, void *, int, void *))vt[3])(o, stm, 0, statbuf, 0, 0);
    else if (slot == 4) r2 = ((SCODE(*)(void *, IStream *, void *, void *, void *, void *, void *, ULONG, int, int *))vt[4])(o, stm, 0, 0, 0, 0, 0, 0, 0, 0);
    else if (slot == 5) r2 = ((SCODE(*)(void *, IStream *, void *, void *, void *, void *, ULONG, int, int *))vt[5])(o, stm, 0, 0, 0, 0, 0, 0, 0);
    else if (slot == 10) { void *blk = 0; ULONG n2 = 0; void *t1, *t2;
      r2 = ((SCODE(*)(void *, IStream *, void **, ULONG *, void *, void *))vt[10])(o, stm, &blk, &n2, &t1, &t2); }
    printf(" rc=0x%08x ms=%lu RESULT\n", (unsigned)r2, (unsigned long)(GetTickCount() - t0));
    done++;
    stm->Release();
    ((HRESULT(*)(void *))vt[2])(o);
  }
  printf("DONE cases=%d done=%d\n", nf, done);
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IONBF, 0);
  AddVectoredExceptionHandler(1, Veh);
  CoInitializeEx(0, COINIT_MULTITHREADED);
  int mode = argc > 1 ? atoi(argv[1]) : 0;
  const char *arg = argc > 2 ? argv[2] : "";
  int slot = argc > 3 ? atoi(argv[3]) : 4;
  ResolveDll();
  HMODULE hm = 0;
  if (hm) {
    char p[MAX_PATH]; GetModuleFileNameA(hm, p, sizeof(p));
    printf("%s ", strrchr(p, '\\') ? strrchr(p, '\\') + 1 : p);
    const char *cands[] = { "MDInit", "MDUninit", "MDConvertStreamToMime", "MDConvertMimeToStream",
                            "MDConvertMimeToMsg", "MDConvertTnefToMsg", "HrMDInit", "DllGetClassObject", 0 };
    for (int i = 0; cands[i]; i++) if (GetProcAddress(hm, cands[i])) printf("exp=%s ", cands[i]);
  }
  if (mode == 0) {
    SCODE a, b, c; void *o1 = NewObj(CLSID_iCal, IID_iCal, &a);
    void *o2 = NewObj(CLSID_vCal, IID_vCal, &b);
    void *o3 = NewObj(CLSID_Parser, IID_Parse, &c);
    printf("\niCal obj=0x%p rc=0x%08x vCal obj=0x%p rc=0x%08x parser obj=0x%p rc=0x%08x\n",
           o1, (unsigned)a, o2, (unsigned)b, o3, (unsigned)c);
    return 0;
  }

  if (mode == 13) {
    ProbeCls("MDCvt_iCal", CLSID_iCal);
    ProbeCls("MimeDirParser", CLSID_Parser);
    ProbeCls("MimeDirItem", CLSID_Item);
    ProbeCls("MapiCvt", CLSID_MapiCvt);
    return 0;
  }
  if (mode == 12) {   // page-heap self test: 64-byte alloc, write one qword past the end
    void *p = malloc(64);
    volatile long long *q = (volatile long long *)p;
    printf("selftest alloc=0x%p writing[8]=.. ", p); fflush(stdout);
    q[8] = 0x4141414141414141LL;
    printf("NOT_DETECTED rc=0x%08x\n", (unsigned)q[8]);
    return 0;
  }
  if (mode == 9) { ParseSweep(arg, argc > 3 ? atoi(argv[3]) : 0, argc > 4 ? atoi(argv[4]) : 0); return 0; }
  if (mode == 14) { ConvSweep(arg, argc > 3 ? atoi(argv[3]) : 4); return 0; }
  if (mode == 7) {
    const CLSID *pc = &CLSID_iCal; const IID *pi = &IID_iCal;
    if (argc > 3 && !strcmp(argv[3], "parser")) { pc = &CLSID_Parser; pi = &IID_Parse; }
    if (argc > 3 && !strcmp(argv[3], "vcal")) { pc = &CLSID_vCal; pi = &IID_vCal; }
    SCODE rc; void *o = NewObj(*pc, *pi, &rc);
    if (!o) { printf("create rc=0x%08x\n", (unsigned)rc); return 3; }
    CollectMods();
    MODULEINFO mi; GetModuleInformation(GetCurrentProcess(), hm, &mi, sizeof(mi));
    void **vt = VT(o);
    if (!hm) { CollectMods(); MODULEINFO mi2; for (int i = 0; i < g_nmod; i++) if (GetModuleInformation(GetCurrentProcess(), g_mods[i], &mi2, sizeof(mi2)) && (char *)vt[0] >= (char *)mi2.lpBaseOfDll && (char *)vt[0] < (char *)mi2.lpBaseOfDll + mi2.SizeOfImage) { hm = g_mods[i]; break; } }
    for (int i = 0; i < 16; i++)
      printf(" [%2d] 0x%p  rva=0x%x\n", i, vt[i], (unsigned)((char *)vt[i] - (char *)mi.lpBaseOfDll));
    return 0;
  }
  if (mode == 8) {
    static const char *exts[] = { "*.ics", "*.vcs", "*.vcf", "*.ifb", "*.mht", "*.eml", 0 };
    static char files[4000][MAX_PATH];
    size_t base = strlen(arg);
    int nf = 0;
    for (int e = 0; exts[e] && nf < 4000; e++) {
      char pat[MAX_PATH]; _snprintf(pat, sizeof(pat), "%s\\%s", arg, exts[e]);
      WIN32_FIND_DATAA fd;
      HANDLE hf = FindFirstFileA(pat, &fd);
      if (hf == INVALID_HANDLE_VALUE) continue;
      do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
          _snprintf(files[nf++], MAX_PATH, "%s\\%s", arg, fd.cFileName);
      } while (nf < 4000 && FindNextFileA(hf, &fd));
      FindClose(hf);
    }
    printf("dir=%s cases=%d slot=%d\n", arg, nf, slot);
    int okc = 0;
    for (int i = 0; i < nf; i++) {
      CLSID cls = (slot == 6) ? CLSID_vCal : CLSID_iCal;
      IID iid = (slot == 6) ? IID_vCal : IID_iCal;
      int sl = (slot == 6) ? 4 : slot;
      SCODE rc; void *o = NewObj(cls, iid, &rc);
      if (!o) { printf("F%04d create rc=0x%08x\n", i, (unsigned)rc); continue; }
      IStream *stm = FileToStream(files[i]);
      if (!stm) { printf("F%04d skip %s\n", i, files[i]); continue; }
      printf("F%04d %s", i, strrchr(files[i], '\\') ? strrchr(files[i], '\\') + 1 : files[i]);
      RunSlot(o, stm, sl);
      printf(" RESULT\n");
      okc++;
      stm->Release();
      ((HRESULT(*)(void *))VT(o)[2])(o);
    }
    printf("DONE cases=%d done=%d\n", nf, okc);
    return 0;
  }
  CLSID cls = (slot == 6) ? CLSID_vCal : CLSID_iCal;
  IID iid = (slot == 6) ? IID_vCal : IID_iCal;
  SCODE rc; void *o = NewObj(cls, iid, &rc);
  if (!o) { printf("create rc=0x%08x\n", (unsigned)rc); return 3; }
  IStream *stm = FileToStream(arg);
  if (!stm) return 4;
  RunSlot(o, stm, slot == 6 ? 4 : slot);
  printf(" RESULT\n");
  return 0;
}
