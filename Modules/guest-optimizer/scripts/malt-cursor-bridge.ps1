# Compliant user-mode Guest cursor state bridge for Malt (com.malt.cursor.0).
# Owner: @DNPMBHC
# Compliance: Read-only standard Win32 desktop APIs only (GetCursorInfo, GetIconInfo,
# GetDIBits, SHQueryUserNotificationState, GetForegroundWindow). Zero hooks, zero DLL
# injection, zero kernel driver changes, zero game process access.
[CmdletBinding()]
param(
    [switch]$AlwaysOverlay,
    [switch]$CompileOnly,
    [string]$OutputExePath = 'C:\ProgramData\Malt\CursorBridge\MaltCursorBridge.exe',
    [string]$SourceOutPath = 'C:\ProgramData\Malt\CursorBridge\MaltCursorBridge.cs'
)

$ErrorActionPreference = 'Stop'

$CSharpSource = @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace MaltCursorBridge
{
    internal static class Program
    {
        private const string DevicePath = @"\\.\Global\com.malt.cursor.0";
        private const uint GENERIC_WRITE = 0x40000000u;
        private const uint OPEN_EXISTING = 3u;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x80u;
        private const int CURSOR_SHOWING = 0x00000001;
        private const int QUNS_RUNNING_D3D_FULL_SCREEN = 3;
        private const uint MONITOR_DEFAULTTONEAREST = 2u;
        private const int BI_RGB = 0;
        private const uint DIB_RGB_COLORS = 0u;
        private const int MAX_CURSOR_DIM = 128;

        [StructLayout(LayoutKind.Sequential)]
        private struct POINT { public int X; public int Y; }

        [StructLayout(LayoutKind.Sequential)]
        private struct RECT { public int Left; public int Top; public int Right; public int Bottom; }

        [StructLayout(LayoutKind.Sequential)]
        private struct CURSORINFO
        {
            public int cbSize;
            public int flags;
            public IntPtr hCursor;
            public POINT ptScreenPos;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ICONINFO
        {
            [MarshalAs(UnmanagedType.Bool)] public bool fIcon;
            public int xHotspot;
            public int yHotspot;
            public IntPtr hbmMask;
            public IntPtr hbmColor;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BITMAP
        {
            public int bmType;
            public int bmWidth;
            public int bmHeight;
            public int bmWidthBytes;
            public ushort bmPlanes;
            public ushort bmBitsPixel;
            public IntPtr bmBits;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BITMAPINFOHEADER
        {
            public uint biSize;
            public int biWidth;
            public int biHeight;
            public ushort biPlanes;
            public ushort biBitCount;
            public uint biCompression;
            public uint biSizeImage;
            public int biXPelsPerMeter;
            public int biYPelsPerMeter;
            public uint biClrUsed;
            public uint biClrImportant;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BITMAPINFO
        {
            public BITMAPINFOHEADER bmiHeader;
            public uint bmiColors;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MONITORINFO
        {
            public int cbSize;
            public RECT rcMonitor;
            public RECT rcWork;
            public uint dwFlags;
        }

        [DllImport("user32.dll")] private static extern bool SetProcessDPIAware();
        [DllImport("user32.dll")] private static extern bool SetProcessDpiAwarenessContext(IntPtr value);
        [DllImport("user32.dll")] private static extern bool GetCursorInfo(ref CURSORINFO pci);
        [DllImport("user32.dll")] private static extern bool GetIconInfo(IntPtr hIcon, out ICONINFO piconinfo);
        [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
        [DllImport("user32.dll")] private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);
        [DllImport("user32.dll")] private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint dwFlags);
        [DllImport("user32.dll")] private static extern bool GetMonitorInfo(IntPtr hMonitor, ref MONITORINFO lpmi);
        [DllImport("user32.dll")] private static extern IntPtr GetDC(IntPtr hWnd);
        [DllImport("user32.dll")] private static extern int ReleaseDC(IntPtr hWnd, IntPtr hDC);

        [DllImport("gdi32.dll")] private static extern int GetObject(IntPtr h, int c, out BITMAP pv);
        [DllImport("gdi32.dll")] private static extern int GetDIBits(IntPtr hdc, IntPtr hbm, uint start, uint cLines, byte[] lpvBits, ref BITMAPINFO lpbmi, uint usage);
        [DllImport("gdi32.dll")] private static extern bool DeleteObject(IntPtr ho);

        [DllImport("shell32.dll")] private static extern int SHQueryUserNotificationState(out int pquns);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFileW(
            string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes,
            uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteFile(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        private static void EnablePerMonitorDpiAwareness()
        {
            try { SetProcessDpiAwarenessContext(new IntPtr(-4)); return; } catch { }
            try { SetProcessDPIAware(); } catch { }
        }

        private static bool IsFullscreenOverlayNeeded(bool alwaysOverlay)
        {
            if (alwaysOverlay) return true;
            try
            {
                int qstate;
                if (SHQueryUserNotificationState(out qstate) == 0 && qstate == QUNS_RUNNING_D3D_FULL_SCREEN)
                {
                    return true;
                }
            }
            catch { }

            IntPtr fg = GetForegroundWindow();
            if (fg == IntPtr.Zero) return false;

            StringBuilder cls = new StringBuilder(128);
            GetClassName(fg, cls, cls.Capacity);
            string className = cls.ToString();
            if (string.Equals(className, "Progman", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(className, "WorkerW", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(className, "Shell_TrayWnd", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(className, "Shell_SecondaryTrayWnd", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(className, "NotifyIconOverflowWindow", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            RECT wr;
            if (!GetWindowRect(fg, out wr)) return false;
            IntPtr mon = MonitorFromWindow(fg, MONITOR_DEFAULTTONEAREST);
            if (mon == IntPtr.Zero) return false;
            MONITORINFO mi = new MONITORINFO();
            mi.cbSize = Marshal.SizeOf(typeof(MONITORINFO));
            if (!GetMonitorInfo(mon, ref mi)) return false;

            int winW = wr.Right - wr.Left;
            int winH = wr.Bottom - wr.Top;
            int monW = mi.rcMonitor.Right - mi.rcMonitor.Left;
            int monH = mi.rcMonitor.Bottom - mi.rcMonitor.Top;
            return winW >= monW - 2 && winH >= monH - 2 && wr.Left <= mi.rcMonitor.Left + 2 && wr.Top <= mi.rcMonitor.Top + 2;
        }

        private static bool CaptureCursorBgra(IntPtr hCursor, out byte[] bgra, out int width, out int height, out int hotX, out int hotY)
        {
            bgra = null;
            width = 0;
            height = 0;
            hotX = 0;
            hotY = 0;

            ICONINFO info;
            if (!GetIconInfo(hCursor, out info)) return false;
            try
            {
                hotX = info.xHotspot;
                hotY = info.yHotspot;

                IntPtr screenDc = GetDC(IntPtr.Zero);
                if (screenDc == IntPtr.Zero) return false;
                try
                {
                    if (info.hbmColor != IntPtr.Zero)
                    {
                        BITMAP bm;
                        if (GetObject(info.hbmColor, Marshal.SizeOf(typeof(BITMAP)), out bm) == 0) return false;
                        int w = Math.Min(Math.Max(bm.bmWidth, 1), MAX_CURSOR_DIM);
                        int h = Math.Min(Math.Max(Math.Abs(bm.bmHeight), 1), MAX_CURSOR_DIM);
                        if (w != bm.bmWidth || h != Math.Abs(bm.bmHeight)) return false;

                        byte[] colorBits = new byte[w * h * 4];
                        BITMAPINFO bmi = new BITMAPINFO();
                        bmi.bmiHeader.biSize = (uint)Marshal.SizeOf(typeof(BITMAPINFOHEADER));
                        bmi.bmiHeader.biWidth = w;
                        bmi.bmiHeader.biHeight = -h;
                        bmi.bmiHeader.biPlanes = 1;
                        bmi.bmiHeader.biBitCount = 32;
                        bmi.bmiHeader.biCompression = BI_RGB;

                        if (GetDIBits(screenDc, info.hbmColor, 0, (uint)h, colorBits, ref bmi, DIB_RGB_COLORS) == 0)
                            return false;

                        bool hasAlpha = false;
                        for (int i = 3; i < colorBits.Length; i += 4)
                        {
                            if (colorBits[i] != 0) { hasAlpha = true; break; }
                        }

                        if (!hasAlpha && info.hbmMask != IntPtr.Zero)
                        {
                            byte[] maskBits = new byte[w * h * 4];
                            BITMAPINFO maskBmi = bmi;
                            if (GetDIBits(screenDc, info.hbmMask, 0, (uint)h, maskBits, ref maskBmi, DIB_RGB_COLORS) != 0)
                            {
                                for (int i = 0; i < colorBits.Length; i += 4)
                                {
                                    bool transparent = (maskBits[i] != 0);
                                    if (transparent)
                                    {
                                        colorBits[i] = 0; colorBits[i + 1] = 0; colorBits[i + 2] = 0; colorBits[i + 3] = 0;
                                    }
                                    else
                                    {
                                        colorBits[i + 3] = 0xFF;
                                    }
                                }
                            }
                        }

                        bgra = colorBits;
                        width = w;
                        height = h;
                        return true;
                    }
                    else if (info.hbmMask != IntPtr.Zero)
                    {
                        BITMAP bm;
                        if (GetObject(info.hbmMask, Marshal.SizeOf(typeof(BITMAP)), out bm) == 0) return false;
                        int w = bm.bmWidth;
                        int fullH = Math.Abs(bm.bmHeight);
                        int h = fullH / 2;
                        if (w <= 0 || h <= 0 || w > MAX_CURSOR_DIM || h > MAX_CURSOR_DIM) return false;

                        byte[] maskBits = new byte[w * fullH * 4];
                        BITMAPINFO bmi = new BITMAPINFO();
                        bmi.bmiHeader.biSize = (uint)Marshal.SizeOf(typeof(BITMAPINFOHEADER));
                        bmi.bmiHeader.biWidth = w;
                        bmi.bmiHeader.biHeight = -fullH;
                        bmi.bmiHeader.biPlanes = 1;
                        bmi.bmiHeader.biBitCount = 32;
                        bmi.bmiHeader.biCompression = BI_RGB;

                        if (GetDIBits(screenDc, info.hbmMask, 0, (uint)fullH, maskBits, ref bmi, DIB_RGB_COLORS) == 0)
                            return false;

                        byte[] outBits = new byte[w * h * 4];
                        int xorBase = w * h * 4;
                        for (int i = 0; i < outBits.Length; i += 4)
                        {
                            bool andSet = maskBits[i] != 0;
                            bool xorSet = maskBits[xorBase + i] != 0;
                            if (andSet && !xorSet)
                            {
                                outBits[i] = 0; outBits[i + 1] = 0; outBits[i + 2] = 0; outBits[i + 3] = 0;
                            }
                            else if (!andSet && !xorSet)
                            {
                                outBits[i] = 0; outBits[i + 1] = 0; outBits[i + 2] = 0; outBits[i + 3] = 0xFF;
                            }
                            else
                            {
                                outBits[i] = 0xFF; outBits[i + 1] = 0xFF; outBits[i + 2] = 0xFF; outBits[i + 3] = 0xFF;
                            }
                        }

                        bgra = outBits;
                        width = w;
                        height = h;
                        return true;
                    }
                    return false;
                }
                finally
                {
                    ReleaseDC(IntPtr.Zero, screenDc);
                }
            }
            finally
            {
                if (info.hbmColor != IntPtr.Zero) DeleteObject(info.hbmColor);
                if (info.hbmMask != IntPtr.Zero) DeleteObject(info.hbmMask);
            }
        }

        private static bool WriteAll(IntPtr handle, byte[] buffer)
        {
            uint written;
            return WriteFile(handle, buffer, (uint)buffer.Length, out written, IntPtr.Zero) && written == (uint)buffer.Length;
        }

        private static void WriteInt32LE(byte[] buf, int off, int val)
        {
            buf[off] = (byte)(val & 0xFF);
            buf[off + 1] = (byte)((val >> 8) & 0xFF);
            buf[off + 2] = (byte)((val >> 16) & 0xFF);
            buf[off + 3] = (byte)((val >> 24) & 0xFF);
        }

        private static void WriteUInt16LE(byte[] buf, int off, ushort val)
        {
            buf[off] = (byte)(val & 0xFF);
            buf[off + 1] = (byte)((val >> 8) & 0xFF);
        }

        // Binary protocol magic "MCB1" (0x4D, 0x43, 0x42, 0x31)
        private static byte[] BuildHideFrame()
        {
            return new byte[] { 0x4D, 0x43, 0x42, 0x31, 0x01 };
        }

        private static byte[] BuildMoveFrame(int x, int y)
        {
            byte[] buf = new byte[13];
            buf[0] = 0x4D; buf[1] = 0x43; buf[2] = 0x42; buf[3] = 0x31; buf[4] = 0x02;
            WriteInt32LE(buf, 5, x);
            WriteInt32LE(buf, 9, y);
            return buf;
        }

        private static byte[] BuildShapeFrame(int x, int y, int width, int height, int hotX, int hotY, bool visible, byte[] bgra)
        {
            byte[] buf = new byte[25 + bgra.Length];
            buf[0] = 0x4D; buf[1] = 0x43; buf[2] = 0x42; buf[3] = 0x31; buf[4] = 0x03;
            WriteInt32LE(buf, 5, x);
            WriteInt32LE(buf, 9, y);
            WriteUInt16LE(buf, 13, (ushort)width);
            WriteUInt16LE(buf, 15, (ushort)height);
            WriteUInt16LE(buf, 17, unchecked((ushort)(short)hotX));
            WriteUInt16LE(buf, 19, unchecked((ushort)(short)hotY));
            WriteInt32LE(buf, 21, visible ? 1 : 0);
            Buffer.BlockCopy(bgra, 0, buf, 25, bgra.Length);
            return buf;
        }

        public static int Main(string[] args)
        {
            bool alwaysOverlay = false;
            if (args != null)
            {
                for (int i = 0; i < args.Length; i++)
                {
                    if (string.Equals(args[i], "--always", StringComparison.OrdinalIgnoreCase))
                    {
                        alwaysOverlay = true;
                    }
                }
            }
            string envMode = Environment.GetEnvironmentVariable("MALT_CURSOR_BRIDGE_MODE");
            if (string.Equals(envMode, "always", StringComparison.OrdinalIgnoreCase))
            {
                alwaysOverlay = true;
            }

            bool createdNew;
            using (Mutex mutex = new Mutex(true, @"Local\MaltCursorBridgeSingleInstance", out createdNew))
            {
                if (!createdNew) return 0;
                EnablePerMonitorDpiAwareness();

                IntPtr port = INVALID_HANDLE_VALUE;
                IntPtr lastCursor = IntPtr.Zero;
                int lastX = int.MinValue;
                int lastY = int.MinValue;
                bool overlayActive = false;
                byte[] hideFrame = BuildHideFrame();

                while (true)
                {
                    if (port == INVALID_HANDLE_VALUE)
                    {
                        port = CreateFileW(DevicePath, GENERIC_WRITE, 3u, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
                        if (port == INVALID_HANDLE_VALUE)
                        {
                            Thread.Sleep(1500);
                            continue;
                        }
                        lastCursor = IntPtr.Zero;
                        lastX = int.MinValue;
                        lastY = int.MinValue;
                        overlayActive = false;
                    }

                    bool fullscreenNeeded = IsFullscreenOverlayNeeded(alwaysOverlay);
                    CURSORINFO ci = new CURSORINFO();
                    ci.cbSize = Marshal.SizeOf(typeof(CURSORINFO));
                    bool cursorShowing = GetCursorInfo(ref ci) && ((ci.flags & CURSOR_SHOWING) != 0) && ci.hCursor != IntPtr.Zero;

                    bool ok = true;
                    if (fullscreenNeeded && cursorShowing)
                    {
                        int x = ci.ptScreenPos.X;
                        int y = ci.ptScreenPos.Y;
                        if (!overlayActive || ci.hCursor != lastCursor)
                        {
                            byte[] bgra;
                            int w, h, hx, hy;
                            if (CaptureCursorBgra(ci.hCursor, out bgra, out w, out h, out hx, out hy))
                            {
                                ok = WriteAll(port, BuildShapeFrame(x, y, w, h, hx, hy, true, bgra));
                                if (ok)
                                {
                                    lastCursor = ci.hCursor;
                                    lastX = x;
                                    lastY = y;
                                    overlayActive = true;
                                }
                            }
                        }
                        else if (x != lastX || y != lastY)
                        {
                            ok = WriteAll(port, BuildMoveFrame(x, y));
                            if (ok)
                            {
                                lastX = x;
                                lastY = y;
                            }
                        }
                    }
                    else
                    {
                        if (overlayActive)
                        {
                            ok = WriteAll(port, hideFrame);
                            if (ok)
                            {
                                overlayActive = false;
                                lastCursor = IntPtr.Zero;
                            }
                        }
                    }

                    if (!ok)
                    {
                        CloseHandle(port);
                        port = INVALID_HANDLE_VALUE;
                        overlayActive = false;
                        lastCursor = IntPtr.Zero;
                        Thread.Sleep(500);
                        continue;
                    }

                    Thread.Sleep(fullscreenNeeded ? 8 : 80);
                }
            }
        }
    }
}
'@

$outDir = Split-Path -Parent $SourceOutPath
if (-not [string]::IsNullOrWhiteSpace($outDir)) {
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
}
Set-Content -LiteralPath $SourceOutPath -Value $CSharpSource -Encoding UTF8

$cscCandidates = @(
    (Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'),
    (Join-Path $env:SystemRoot 'Microsoft.NET\Framework\v4.0.30319\csc.exe')
)
$csc = $cscCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

if ($CompileOnly) {
    if ($null -ne $csc) {
        $exeDir = Split-Path -Parent $OutputExePath
        if (-not [string]::IsNullOrWhiteSpace($exeDir)) {
            New-Item -ItemType Directory -Force -Path $exeDir | Out-Null
        }
        & $csc /nologo /optimize+ /target:winexe "/out:$OutputExePath" $SourceOutPath | Out-Null
        if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $OutputExePath)) {
            Write-Output "MALT_CURSOR_BRIDGE_COMPILED=$OutputExePath"
            exit 0
        }
    }
    Write-Output "MALT_CURSOR_BRIDGE_SCRIPT_FALLBACK=$PSCommandPath"
    exit 0
}

Add-Type -TypeDefinition $CSharpSource -Language CSharp -ErrorAction Stop
$bridgeArgs = if ($AlwaysOverlay) { @('--always') } else { @() }
[MaltCursorBridge.Program]::Main($bridgeArgs)
