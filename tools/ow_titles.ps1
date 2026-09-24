$src = @'
using System; using System.Text; using System.Runtime.InteropServices; using System.Collections.Generic;
public class OW {
  delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc cb, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint p);
  public static List<string> Titles(uint only) {
    var r = new List<string>();
    EnumWindows((h,l) => { uint p; GetWindowThreadProcessId(h, out p);
      if (only != 0 && p != only) return true;
      if (!IsWindowVisible(h)) return true;
      var t = new StringBuilder(1024); GetWindowTextW(h, t, 1024);
      if (t.Length > 0) r.Add(p + ":" + t.ToString());
      return true; }, IntPtr.Zero);
    return r; }
}
'@
if (-not ('OW' -as [type])) { Add-Type -TypeDefinition $src }
