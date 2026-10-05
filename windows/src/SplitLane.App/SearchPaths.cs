using System.Runtime.InteropServices;

// Every P/Invoke in this assembly that does not say otherwise resolves its library from System32 only
// (SL-SEC-015). The default search would also try the application directory, the current directory and
// PATH. WinDivert, the one non-system library, is loaded by absolute path through its own resolver.
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
