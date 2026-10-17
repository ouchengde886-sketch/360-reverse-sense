# 读取 DSMain 扫描结果对话框的内容
Add-Type @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class Dlg {
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr p);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint msg, IntPtr wp, StringBuilder lp);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint msg, IntPtr wp, IntPtr lp);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  public delegate bool EnumProc(IntPtr h, IntPtr p);
  public const uint WM_GETTEXT = 0x000D;
  public const uint WM_GETTEXTLENGTH = 0x000E;
  public static string Text(IntPtr h) {
    int n = (int)SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
    if (n <= 0) return "";
    var sb = new StringBuilder(n + 2);
    SendMessageW(h, WM_GETTEXT, (IntPtr)(n + 1), sb);
    return sb.ToString();
  }
  public static List<IntPtr> Tops(uint target) {
    var res = new List<IntPtr>();
    EnumWindows((h,p) => { uint pid; GetWindowThreadProcessId(h, out pid); if (pid==target) res.Add(h); return true; }, IntPtr.Zero);
    return res;
  }
  public static List<IntPtr> Kids(IntPtr parent) {
    var res = new List<IntPtr>();
    EnumChildWindows(parent, (h,p) => { res.Add(h); return true; }, IntPtr.Zero);
    return res;
  }
  public static string Cls(IntPtr h) { var c = new StringBuilder(256); GetClassNameW(h,c,256); return c.ToString(); }
}
"@ -ErrorAction SilentlyContinue

$pid360 = 18984
$tops = [Dlg]::Tops($pid360)
foreach ($t in $tops) {
  $cls = [Dlg]::Cls($t)
  $txt = [Dlg]::Text($t)
  $vis = [Dlg]::IsWindowVisible($t)
  if ($cls -eq '#32770' -or $txt -ne '') {
    Write-Host ("=== 顶层窗口 hwnd=0x{0:X8} class='{1}' vis={2} title='{3}' ===" -f $t.ToInt64(), $cls, $vis, $txt)
    $kids = [Dlg]::Kids($t)
    Write-Host ("  子控件数: {0}" -f $kids.Count)
    foreach ($k in $kids) {
      $kt = [Dlg]::Text($k)
      if ($kt -and $kt.Trim().Length -gt 0) {
        Write-Host ("    [{0}] '{1}'" -f [Dlg]::Cls($k), $kt.Trim())
      }
    }
  }
}