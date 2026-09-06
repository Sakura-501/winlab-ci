// MiniDbg v13: v12 + dynamic resolver discovery.
// ctl options added: chain=A:B:C (walk qword ptrs from rcx), dynbp (arm INT3 at [vtable+0x2C0]
// of chain-final object), wstr=OFF (read wchar_t* at rcx+OFF, log string).
// Resolver hits (name "resolver") dump rdx as wide string + 32 bytes at r8 (out struct).
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

class MiniDbg
{
    const uint DEBUG_PROCESS = 0x00000001;
    const uint DBG_CONTINUE = 0x00010002;
    const uint DBG_EXCEPTION_NOT_HANDLED = 0x80010001;
    const int EXCEPTION_DEBUG_EVENT = 1;
    const int CREATE_PROCESS_DEBUG_EVENT = 3;
    const int EXIT_PROCESS_DEBUG_EVENT = 5;
    const int LOAD_DLL_DEBUG_EVENT = 6;
    const uint EXCEPTION_BREAKPOINT = 0x80000003;
    const uint EXCEPTION_SINGLE_STEP = 0x80000004;

    [StructLayout(LayoutKind.Sequential)]
    struct STARTUPINFO { public int cb; public IntPtr r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11; }
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public uint pid; public uint tid; }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessW(string app, string cmd, IntPtr pa, IntPtr ta, bool inh, uint flags, IntPtr env, string cwd, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WaitForDebugEvent(byte[] ev, int ms);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ContinueDebugEvent(uint pid, uint tid, uint status);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DebugSetProcessKillOnExit(bool kill);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenThread(uint access, bool inherit, uint tid);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetThreadContext(IntPtr h, IntPtr ctx);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetThreadContext(IntPtr h, IntPtr ctx);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr read);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr written);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetFileInformationByHandleEx(IntPtr hFile, int cls, IntPtr info, uint size);
    [DllImport("kernel32.dll")]
    static extern bool FlushInstructionCache(IntPtr h, IntPtr addr, IntPtr size);

    static string logPath;
    static StreamWriter log;
    static IntPtr hProc = IntPtr.Zero;
    static Dictionary<ulong, BpInfo> bps = new Dictionary<ulong, BpInfo>();
    static Dictionary<uint, IntPtr> procHandles = new Dictionary<uint, IntPtr>();
    static Dictionary<ulong, string> rvaNames = new Dictionary<ulong, string>();
    static List<ulong> readOffsets = new List<ulong>();
    static Dictionary<string, byte[]> patchOnHit = new Dictionary<string, byte[]>();
    static Dictionary<string, int> patchCount = new Dictionary<string, int>();

    class BpInfo { public byte[] OrigBytes; public byte[] Patch; public ulong Rva; public int Hits; public bool InMso; }
    static List<ulong> chainOffs = new List<ulong>();
    static Dictionary<uint, ulong> msoBase = new Dictionary<uint, ulong>();
    static Dictionary<ulong, string> msoNames = new Dictionary<ulong, string>();
    static bool dynbp = false;
    static ulong wstrOff = 0;
    static bool resolverArmed = false;
    static ulong resolverVa = 0;
    static int resolverLogs = 0;
    static int primaryHits = 0;

    static void L(string s)
    {
        string line = DateTime.Now.ToString("HH:mm:ss.fff") + " " + s;
        log.WriteLine(line); log.Flush();
        Console.WriteLine(line);
    }

    static string DllNameOfHandle(IntPtr hFile)
    {
        if (hFile == IntPtr.Zero) return "";
        IntPtr buf = Marshal.AllocHGlobal(2048);
        try
        {
            if (!GetFileInformationByHandleEx(hFile, 2, buf, 2048)) return "";
            int len = Marshal.ReadInt32(buf, 0);
            if (len <= 0 || len > 2000) return "";
            byte[] nb = new byte[len];
            Marshal.Copy(new IntPtr(buf.ToInt64() + 4), nb, 0, len);
            return Encoding.Unicode.GetString(nb);
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    static ulong GetReg(IntPtr ctx, int off) { return (ulong)Marshal.ReadInt64(ctx, off); }
    static void SetReg(IntPtr ctx, int off, ulong v) { Marshal.WriteInt64(ctx, off, (long)v); }

    static bool ReadMem(ulong addr, int size, out byte[] buf)
    {
        buf = new byte[size]; IntPtr rd;
        if (!ReadProcessMemory(hProc, new IntPtr((long)addr), buf, new IntPtr(size), out rd)) return false;
        return rd.ToInt64() == size;
    }

    static bool ReadQ(ulong addr, out ulong v)
    {
        v = 0; byte[] b;
        if (!ReadMem(addr, 8, out b)) return false;
        v = BitConverter.ToUInt64(b, 0); return true;
    }

    static string WStrAt(ulong addr)
    {
        byte[] b;
        if (addr == 0 || !ReadMem(addr, 256, out b)) return "<unreadable>";
        int n = 0;
        while (n + 1 < b.Length && !(b[n] == 0 && b[n + 1] == 0)) n += 2;
        if (n == 0) return "<empty>";
        string s = Encoding.Unicode.GetString(b, 0, n);
        if (s.Length > 90) s = s.Substring(0, 90) + "...";
        foreach (char c in s) if (c < 0x20) return "<binary>";
        return "'" + s + "'";
    }

    static string Hex(byte[] b)
    {
        StringBuilder sb = new StringBuilder();
        foreach (byte x in b) sb.Append(x.ToString("X2") + " ");
        return sb.ToString();
    }

    static void ArmResolver(ulong va)
    {
        if (resolverArmed || va == 0) return;
        byte[] orig = new byte[1]; IntPtr rd, wr;
        if (!ReadProcessMemory(hProc, new IntPtr((long)va), orig, new IntPtr(1), out rd)) { L("DYNBP read fail at 0x" + va.ToString("X")); return; }
        byte[] cc = new byte[] { 0xCC };
        if (!WriteProcessMemory(hProc, new IntPtr((long)va), cc, new IntPtr(1), out wr)) { L("DYNBP write fail at 0x" + va.ToString("X")); return; }
        BpInfo bi = new BpInfo(); bi.Rva = 0; bi.Patch = cc; bi.OrigBytes = orig;
        bps[va] = bi;
        resolverArmed = true; resolverVa = va;
        L("DYNBP ARMED resolver at 0x" + va.ToString("X") + " orig=" + orig[0].ToString("X2"));
    }

    static int Main(string[] args)
    {
        if (args.Length < 3)
        {
            Console.WriteLine("usage: minidbg <WINWORD> <doc|-> -- secs rva=name[,rva=name] [chain=A:B:C,dynbp,wstr=OFF,readoffs...]");
            return 2;
        }
        string word = args[0];
        int sep = Array.IndexOf(args, "--");
        string[] dbgArgs; string[] ctl;
        if (sep >= 0) { dbgArgs = new string[sep - 1]; Array.Copy(args, 1, dbgArgs, 0, sep - 1); ctl = new string[args.Length - sep - 1]; Array.Copy(args, sep + 1, ctl, 0, args.Length - sep - 1); }
        else { Console.WriteLine("need --"); return 2; }
        StringBuilder sbc = new StringBuilder();
        foreach (string a in dbgArgs) { if (sbc.Length > 0) sbc.Append(" "); sbc.Append("\"" + a.Replace("\"\"", "\"\"\"") + "\""); }
        string docPath = sbc.ToString();
        int seconds = int.Parse(ctl[0]);
        foreach (string part in ctl[1].Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
        {
            string[] kv = part.Split('=');
            string nm = kv.Length > 1 ? kv[1] : ("rva_" + kv[0]);
            ulong rva = Convert.ToUInt64(kv[0], 16);
            rvaNames[rva] = nm;
        }
        for (int i = 2; i < ctl.Length; i++)
        {
            foreach (string o in ctl[i].Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (o == "dynbp") { dynbp = true; continue; }
                if (o.StartsWith("chain="))
                {
                    foreach (string p in o.Substring(6).Split(new char[] { ':' }, StringSplitOptions.RemoveEmptyEntries))
                        chainOffs.Add(Convert.ToUInt64(p, 16));
                    continue;
                }
                if (o.StartsWith("wstr=")) { wstrOff = Convert.ToUInt64(o.Substring(5), 16); continue; }
                if (o.StartsWith("mso="))
                {
                    string[] pc = o.Substring(4).Split(new char[] { ':' }, 2);
                    msoNames[Convert.ToUInt64(pc[0], 16)] = pc.Length > 1 ? pc[1] : ("mso_" + pc[0]);
                    continue;
                }
                if (o.StartsWith("patch="))
                {
                    string body = o.Substring(6);
                    string[] c = body.Split(new char[] { ':' }, 2);
                    byte[] pb = new byte[c[1].Length / 2];
                    for (int j = 0; j < pb.Length; j++) pb[j] = Convert.ToByte(c[1].Substring(j * 2, 2), 16);
                    patchOnHit[c[0]] = pb; patchCount[c[0]] = 0;
                    continue;
                }
                readOffsets.Add(Convert.ToUInt64(o, 16));
            }
        }
        logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "minidbg_" + DateTime.Now.ToString("HHmmss") + ".log");
        log = new StreamWriter(logPath);
        L("== minidbg13 start; doc=" + docPath + " secs=" + seconds + " chain=[" +
          string.Join(",", chainOffs.ConvertAll(x => "0x" + x.ToString("X")).ToArray()) + "] dynbp=" + dynbp + " wstr=0x" + wstrOff.ToString("X"));

        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        STARTUPINFO si = new STARTUPINFO(); si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
        string cmdl = "\"" + word + "\" " + (docPath == "-" ? "" : docPath);
        if (!CreateProcessW(null, cmdl, IntPtr.Zero, IntPtr.Zero, false, DEBUG_PROCESS, IntPtr.Zero, null, ref si, out pi))
        {
            L("CreateProcess FAILED err=" + Marshal.GetLastWin32Error());
            return 1;
        }
        hProc = pi.hProcess;
        L("spawned pid=" + pi.pid);
        DebugSetProcessKillOnExit(false);

        DateTime t0 = DateTime.Now;
        byte[] ev = new byte[512];
        bool initialBp = false;
        bool exited = false;
        while (!exited)
        {
            if ((DateTime.Now - t0).TotalSeconds > seconds) { L("timeout reached, detaching"); break; }
            if (!WaitForDebugEvent(ev, 500)) continue;
            uint code = BitConverter.ToUInt32(ev, 0);
            uint pid = BitConverter.ToUInt32(ev, 4);
            uint tid = BitConverter.ToUInt32(ev, 8);
            uint status = DBG_CONTINUE;

            if (code == 3)
            {
                IntPtr hFile = new IntPtr(BitConverter.ToInt64(ev, 16));
                IntPtr hP = new IntPtr(BitConverter.ToInt64(ev, 24));
                IntPtr hT = new IntPtr(BitConverter.ToInt64(ev, 32));
                ulong img = BitConverter.ToUInt64(ev, 40);
                procHandles[pid] = hP;
                L(string.Format("createproc pid={0} img=0x{1:X}", pid, img));
                CloseHandle(hT);
                if (hFile != IntPtr.Zero) CloseHandle(hFile);
            }
            else if (code == EXIT_PROCESS_DEBUG_EVENT)
            {
                L("process " + pid + " exit");
                procHandles.Remove(pid);
                if (pid == pi.pid) exited = true;
            }
            else if (code == LOAD_DLL_DEBUG_EVENT)
            {
                IntPtr hFile = new IntPtr(BitConverter.ToInt64(ev, 16));
                ulong baseDll = BitConverter.ToUInt64(ev, 24);
                string nm = DllNameOfHandle(hFile);
                if (nm.Length == 0) nm = "(unknown)";
                if (nm.ToLower().EndsWith("\\mso.dll") && msoNames.Count > 0)
                {
                    IntPtr savedProcM = hProc;
                    if (procHandles.ContainsKey(pid)) hProc = procHandles[pid];
                    msoBase[pid] = baseDll;
                    L("mso.dll loaded in pid=" + pid + " base=0x" + baseDll.ToString("X"));
                    foreach (KeyValuePair<ulong, string> kv in msoNames)
                    {
                        ulong addr = baseDll + kv.Key;
                        byte[] orig = new byte[1]; IntPtr rd, wr;
                        if (ReadProcessMemory(hProc, new IntPtr((long)addr), orig, new IntPtr(1), out rd))
                        {
                            byte[] cc = new byte[] { 0xCC };
                            if (WriteProcessMemory(hProc, new IntPtr((long)addr), cc, new IntPtr(1), out wr))
                            {
                                BpInfo bi = new BpInfo(); bi.Rva = kv.Key; bi.Patch = cc; bi.OrigBytes = orig; bi.InMso = true;
                                bps[addr] = bi;
                                L("BP set " + kv.Value + " @ mso+0x" + kv.Key.ToString("X") + " (0x" + addr.ToString("X") + ")");
                            }
                        }
                    }
                    hProc = savedProcM;
                }
                if (nm.ToLower().EndsWith("\\wwlib.dll"))
                {
                    IntPtr savedProc = hProc;
                    if (procHandles.ContainsKey(pid)) hProc = procHandles[pid];
                    L("wwlib.dll loaded in pid=" + pid + " base=0x" + baseDll.ToString("X"));
                    foreach (KeyValuePair<ulong, string> kv in rvaNames)
                    {
                        ulong addr = baseDll + kv.Key;
                        byte[] orig = new byte[1]; IntPtr rd, wr;
                        if (ReadProcessMemory(hProc, new IntPtr((long)addr), orig, new IntPtr(1), out rd))
                        {
                            byte[] cc = new byte[] { 0xCC };
                            if (WriteProcessMemory(hProc, new IntPtr((long)addr), cc, new IntPtr(1), out wr))
                            {
                                BpInfo bi = new BpInfo(); bi.Rva = kv.Key; bi.Patch = cc; bi.OrigBytes = orig;
                                bps[addr] = bi;
                                L("BP set " + kv.Value + " @ wwlib+0x" + kv.Key.ToString("X") + " (0x" + addr.ToString("X") + ")");
                            }
                        }
                    }
                    hProc = savedProc;
                }
            }
            else if (code == EXCEPTION_DEBUG_EVENT)
            {
                uint exCode = BitConverter.ToUInt32(ev, 16);
                ulong exAddr = BitConverter.ToUInt64(ev, 32);
                uint firstChance = BitConverter.ToUInt32(ev, 168);
                IntPtr savedProc2 = hProc;
                if (procHandles.ContainsKey(pid)) hProc = procHandles[pid];
                bool bpHit = bps.ContainsKey(exAddr) && exCode == EXCEPTION_BREAKPOINT;
                if (bpHit)
                {
                    BpInfo bi = bps[exAddr];
                    bi.Hits++;
                    bool isResolver = resolverArmed && exAddr == resolverVa;
                    string nm = isResolver ? "resolver" : (bi.InMso ? msoNames[bi.Rva] : rvaNames[bi.Rva]);
                    IntPtr hT = OpenThread(0x0018 | 0x0002 | 0x0008 | 0x0010 | 0x0020, false, tid);
                    IntPtr ctx = Marshal.AllocHGlobal(1264 + 16);
                    IntPtr ctxA = new IntPtr((ctx.ToInt64() + 15) & ~15);
                    try
                    {
                        Marshal.WriteInt32(ctxA, 0x30, 0x100007);
                        if (GetThreadContext(hT, ctxA))
                        {
                            ulong rcx = GetReg(ctxA, 0x80), rdx = GetReg(ctxA, 0x88), r8 = GetReg(ctxA, 0xB8);
                            ulong rsp = GetReg(ctxA, 0x98), rip = GetReg(ctxA, 0xF8);
                            if (isResolver)
                            {
                                resolverLogs++;
                                if (resolverLogs <= 500)
                                    L("RESOLVER #" + bi.Hits + " this=0x" + rcx.ToString("X") + " name=" + WStrAt(rdx) + " out=0x" + r8.ToString("X"));
                                if (r8 != 0)
                                {
                                    byte[] oj;
                                    if (ReadMem(r8, 16, out oj) && resolverLogs <= 500)
                                        L("   OUT " + Hex(oj));
                                }
                            }
                            else if (bi.InMso)
                            {
                                L("MSOHIT " + nm + " #" + bi.Hits + " id(rcx)=0x" + rcx.ToString("X") + " elemsize(rdx)=" + rdx.ToString() + " r8=0x" + r8.ToString("X"));
                                byte[] ret8m;
                                if (ReadMem(rsp, 8, out ret8m))
                                    L("   RET=[rsp]=0x" + BitConverter.ToUInt64(ret8m, 0).ToString("X"));
                            }
                            else
                            {
                                L("HIT " + nm + " #" + bi.Hits + " rip=0x" + rip.ToString("X") + " rcx=0x" + rcx.ToString("X") + " rdx=0x" + rdx.ToString("X"));
                                primaryHits++;
                                foreach (ulong off in readOffsets)
                                {
                                    byte[] q = new byte[8];
                                    if (rcx != 0 && ReadMem(rcx + off, 8, out q))
                                        L("   [rcx+0x" + off.ToString("X") + "]=0x" + BitConverter.ToUInt64(q, 0).ToString("X"));
                                }
                                if (wstrOff != 0 && rcx != 0)
                                {
                                    byte[] p = new byte[8];
                                    if (ReadMem(rcx + wstrOff, 8, out p))
                                        L("   NAME[rcx+0x" + wstrOff.ToString("X") + "]=" + WStrAt(BitConverter.ToUInt64(p, 0)));
                                }
                                if (dynbp && chainOffs.Count > 0 && primaryHits <= 5)
                                {
                                    ulong q = rcx; bool ok = q != 0;
                                    foreach (ulong off in chainOffs)
                                    {
                                        if (!ok || q == 0) { ok = false; break; }
                                        ulong nq;
                                        if (!ReadQ(q + off, out nq)) { ok = false; L("   CHAIN fail at off 0x" + off.ToString("X")); break; }
                                        q = nq;
                                        L("   CHAIN +0x" + off.ToString("X") + " -> 0x" + q.ToString("X"));
                                    }
                                    if (ok && q != 0)
                                    {
                                        ulong vtbl;
                                        if (ReadQ(q, out vtbl) && vtbl != 0)
                                        {
                                            L("   VTBL=0x" + vtbl.ToString("X"));
                                            ulong res;
                                            if (ReadQ(vtbl + 0x2C0, out res))
                                            {
                                                L("   RESOLVER=[vtbl+0x2C0]=0x" + res.ToString("X"));
                                                ArmResolver(res);
                                            }
                                        }
                                    }
                                }
                                byte[] pb;
                                if (patchOnHit.TryGetValue(nm + "@rcx", out pb) && rcx != 0)
                                {
                                    patchCount[nm + "@rcx"] = patchCount[nm + "@rcx"] + 1;
                                    IntPtr wr3;
                                    if (WriteProcessMemory(hProc, new IntPtr((long)rcx), pb, new IntPtr(pb.Length), out wr3))
                                    { FlushInstructionCache(hProc, new IntPtr((long)rcx), new IntPtr(pb.Length)); L("   PATCHED [rcx] " + BitConverter.ToString(pb).Replace("-", " ")); }
                                }
                                byte[] pb2;
                                if (patchOnHit.TryGetValue(nm + "@rdx", out pb2) && rdx != 0)
                                {
                                    patchCount[nm + "@rdx"] = patchCount[nm + "@rdx"] + 1;
                                    IntPtr wr4;
                                    if (WriteProcessMemory(hProc, new IntPtr((long)rdx), pb2, new IntPtr(pb2.Length), out wr4))
                                    { FlushInstructionCache(hProc, new IntPtr((long)rdx), new IntPtr(pb2.Length)); L("   PATCHED [rdx] " + BitConverter.ToString(pb2).Replace("-", " ")); }
                                }
                            }
                        }
                        // restore original instruction, rewind rip
                        IntPtr wr;
                        WriteProcessMemory(hProc, new IntPtr((long)exAddr), bi.OrigBytes, new IntPtr(bi.OrigBytes.Length), out wr);
                        FlushInstructionCache(hProc, new IntPtr((long)exAddr), new IntPtr(bi.OrigBytes.Length));
                        SetReg(ctxA, 0xF8, exAddr);
                        SetThreadContext(hT, ctxA);
                        FlushInstructionCache(hProc, new IntPtr((long)exAddr), new IntPtr(1));
                    }
                    finally { Marshal.FreeHGlobal(ctx); if (hT != IntPtr.Zero) CloseHandle(hT); hProc = savedProc2; }
                }
                else if (exCode == EXCEPTION_BREAKPOINT && !initialBp)
                {
                    initialBp = true;
                    L("initial breakpoint at 0x" + exAddr.ToString("X"));
                }
                else
                {
                    if (exCode != 0x80000003 && exCode != 0x80000004 && exCode != 0x406D1388)
                    {
                        L("exception " + (firstChance != 0 ? "1st" : "2ND") + " 0x" + exCode.ToString("X8") + " at 0x" + exAddr.ToString("X"));
                        if (exCode == 0xC0000005 || exCode == 0xC0000409)
                        {
                            IntPtr hT2 = OpenThread(0x0018 | 0x0002 | 0x0008 | 0x0010 | 0x0020, false, tid);
                            IntPtr ctx2 = Marshal.AllocHGlobal(1264 + 16);
                            IntPtr ctx2A = new IntPtr((ctx2.ToInt64() + 15) & ~15);
                            try
                            {
                                Marshal.WriteInt32(ctx2A, 0x30, 0x100007);
                                if (GetThreadContext(hT2, ctx2A))
                                {
                                    ulong rcx2 = GetReg(ctx2A, 0x80), rdx2 = GetReg(ctx2A, 0x88), rsp2 = GetReg(ctx2A, 0x98), rip2 = GetReg(ctx2A, 0xF8);
                                    L("   CRASHCTX rip=0x" + rip2.ToString("X") + " rcx=0x" + rcx2.ToString("X") + " rdx=0x" + rdx2.ToString("X"));
                                    byte[] st;
                                    if (ReadMem(rsp2, 0x300, out st))
                                    {
                                        StringBuilder ss = new StringBuilder();
                                        for (int k = 0; k + 8 <= st.Length; k += 8)
                                        {
                                            ulong v = BitConverter.ToUInt64(st, k);
                                            if (v >= 0x7FF000000000 && v < 0x800000000000) ss.Append("0x" + v.ToString("X") + " ");
                                        }
                                        L("   STACKRET " + ss.ToString());
                                    }
                                }
                            }
                            finally { Marshal.FreeHGlobal(ctx2); if (hT2 != IntPtr.Zero) CloseHandle(hT2); }
                        }
                    }
                    status = DBG_EXCEPTION_NOT_HANDLED;
                }
            }
            ContinueDebugEvent(pid, tid, status);
        }
        L("== minidbg13 end; primaryHits=" + primaryHits + " resolverLogs=" + resolverLogs);
        log.Close();
        return 0;
    }
}
