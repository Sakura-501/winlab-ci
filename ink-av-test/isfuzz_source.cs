using System;
using System.IO;
using System.Threading;
using System.Collections.Generic;
using Windows.Storage.Streams;
using Windows.UI.Input.Inking;
using Windows.Foundation;

class IsfFuzz {
    static void WaitOp(IAsyncInfo op) {
        while (op.Status == AsyncStatus.Started) Thread.Sleep(5);
    }
    static void Log(string s) { Console.WriteLine(s); Console.Out.Flush(); }

    static void MakeGoodIsf() {
        var sc = new InkStrokeContainer();
        var builder = new InkStrokeBuilder();
        var rp = new List<Windows.Foundation.Point>();
        for (int i = 0; i < 10; i++) rp.Add(new Windows.Foundation.Point(50 + i * 20, 100 + (i % 3) * 10));
        var stroke = builder.CreateStroke(rp as IEnumerable<Windows.Foundation.Point>);
        Log("  stroke built: " + (stroke == null ? "NULL" : "ok"));
        sc.AddStroke(stroke);
        var ms = new InMemoryRandomAccessStream();
        var saveOp = sc.SaveAsync(ms);
        WaitOp(saveOp);
        Log("  save status=" + saveOp.Status);
        var dr = new DataReader(ms.GetInputStreamAt(0));
        var lo = dr.LoadAsync((uint)ms.Size);
        WaitOp(lo);
        byte[] b = new byte[ms.Size];
        dr.ReadBytes(b);
        File.WriteAllBytes(@"C:\isffuzz\good.isf", b);
        Log("  GOODISF bytes=" + b.Length + " head=" + BitConverter.ToString(b, 0, Math.Min(8, b.Length)));
        var ms2 = new InMemoryRandomAccessStream();
        var saveOp2 = sc.SaveAsync(ms2, (InkPersistenceFormat)1);
        WaitOp(saveOp2);
        var dr2 = new DataReader(ms2.GetInputStreamAt(0));
        var lo2 = dr2.LoadAsync((uint)ms2.Size);
        WaitOp(lo2);
        byte[] b2 = new byte[ms2.Size];
        dr2.ReadBytes(b2);
        File.WriteAllBytes(@"C:\isffuzz\goodraw.isf", b2);
        Log("  GOODRAW bytes=" + b2.Length + " head=" + BitConverter.ToString(b2, 0, Math.Min(8, b2.Length)));
    }

    [System.STAThread]
    static void Main(string[] args) {
        string dir = args[0];
        string cur = args.Length > 1 ? args[1] : "cur.txt";
        Log("START");
        try { MakeGoodIsf(); } catch (Exception ex) { Log("GOODISF FAILED " + ex.GetType().Name + ": " + ex.Message + " HR=0x" + ex.HResult.ToString("X8")); }
        string[] files = Directory.GetFiles(dir, "*.isf");
        // fuzz mode: use the directory argument as-is
        foreach (var f in files) {
            File.WriteAllText(cur, f);
            byte[] bytes = File.ReadAllBytes(f);
            Log("FILE " + f + " bytes=" + bytes.Length + " head=" + BitConverter.ToString(bytes, 0, Math.Min(8, bytes.Length)));
            try {
                var sc = new InkStrokeContainer();
                var ms = new InMemoryRandomAccessStream();
                var dw = new DataWriter(ms);
                dw.WriteBytes(bytes);
                var so = dw.StoreAsync();
                WaitOp(so);
                Log("  step3 store ok written=" + so.GetResults());
                var fo = dw.FlushAsync();
                WaitOp(fo);
                Log("  step4 flush ok " + fo.GetResults());
                dw.DetachStream();
                ms.Seek(0);
                var loadOp = sc.LoadAsync(ms);
                WaitOp(loadOp);
                if (loadOp.Status == AsyncStatus.Error) Log("  LOAD-ERRCODE 0x" + loadOp.ErrorCode.HResult.ToString("X8"));
                else Log("  OK strokes=" + sc.GetStrokes().Count);
            } catch (Exception e3) {
                Exception root = e3;
                while (root.InnerException != null) root = root.InnerException;
                Log("  FAIL-LOAD " + root.GetType().Name + " HR=0x" + root.HResult.ToString("X8"));
            }
        }
        Log("BATCH-DONE");
    }
}
