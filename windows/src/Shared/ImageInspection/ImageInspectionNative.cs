using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SplitLane.Platform;

/// <summary>The Win32 entry points image inspection needs.</summary>
/// <remarks>
/// <para>
/// <c>DllImport</c> throughout, where the engine would otherwise use <c>LibraryImport</c>: this source
/// is compiled into the App as well, the App does not allow unsafe code, and the
/// <c>LibraryImport</c> generator emits unsafe stubs (SYSLIB1062). Every signature is either
/// blittable or uses a built-in marshaller, so the runtime-generated stubs are cheap.
/// </para>
/// <para>
/// Every import is restricted to System32. The engine runs as LocalSystem and loads
/// <c>wintrust.dll</c> on first use; a search order that included the application directory would
/// let a planted DLL of that name run with the engine's privileges.
/// </para>
/// </remarks>
internal static class ImageInspectionNative
{
    internal const uint GenericRead = 0x8000_0000;
    internal const uint FileReadAttributes = 0x0080;
    internal const uint FileShareRead = 0x1;
    internal const uint FileShareWrite = 0x2;
    internal const uint FileShareDelete = 0x4;
    internal const uint OpenExisting = 3;
    internal const uint FileFlagSequentialScan = 0x0800_0000;
    internal const uint FileBegin = 0;

    internal const uint ProcessQueryLimitedInformation = 0x1000;
    internal const int ErrorSuccess = 0;
    internal const int ErrorInsufficientBuffer = 122;
    internal const int AppModelErrorNoPackage = 15700;

    // WinVerifyTrust (wintrust.h / softpub.h).
    internal static readonly Guid WinTrustActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    internal static readonly nint InvalidHandleValue = -1;

    internal const uint WtdUiNone = 2;
    internal const uint WtdRevokeNone = 0;
    internal const uint WtdChoiceFile = 1;
    internal const uint WtdChoiceCatalog = 2;
    internal const uint WtdStateActionVerify = 1;
    internal const uint WtdStateActionClose = 2;
    internal const uint WtdRevocationCheckNone = 0x0000_0010;
    internal const uint WtdCacheOnlyUrlRetrieval = 0x0000_1000;

    internal const int TrustENoSignature = unchecked((int)0x800B_0100);
    internal const int TrustESubjectFormUnknown = unchecked((int)0x800B_0003);
    internal const int TrustEProviderUnknown = unchecked((int)0x800B_0001);

    /// <summary><c>MAX_PATH</c>, the fixed size of <c>CATALOG_INFO.wszCatalogFile</c>.</summary>
    internal const int MaxPath = 260;

    /// <summary><c>BY_HANDLE_FILE_INFORMATION</c>. Every field is 4-byte, so there is no padding.</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public uint CreationTimeLow;
        public uint CreationTimeHigh;
        public uint LastAccessTimeLow;
        public uint LastAccessTimeHigh;
        public uint LastWriteTimeLow;
        public uint LastWriteTimeHigh;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    /// <summary>
    /// <c>WINTRUST_DATA</c> including the Windows 8 <c>pSignatureSettings</c> member; 88 bytes on x64.
    /// </summary>
    /// <remarks>
    /// Offsets on x64 with natural alignment: cbStruct 0, pPolicyCallbackData 8, pSIPClientData 16,
    /// dwUIChoice 24, fdwRevocationChecks 28, dwUnionChoice 32, union pointer 40, dwStateAction 48,
    /// hWVTStateData 56, pwszURLReference 64, dwProvFlags 72, dwUIContext 76, pSignatureSettings 80.
    /// </remarks>
    [StructLayout(LayoutKind.Sequential)]
    internal struct WinTrustData
    {
        public uint StructSize;
        public nint PolicyCallbackData;
        public nint SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public nint Info;
        public uint StateAction;
        public nint StateData;
        public nint UrlReference;
        public uint ProvFlags;
        public uint UiContext;
        public nint SignatureSettings;
    }

    /// <summary><c>WINTRUST_FILE_INFO</c>; 32 bytes on x64 (path 8, hFile 16, pgKnownSubject 24).</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct WinTrustFileInfo
    {
        public uint StructSize;
        public nint FilePath;
        public nint File;
        public nint KnownSubject;
    }

    /// <summary>
    /// <c>WINTRUST_CATALOG_INFO</c> including the Windows 8 <c>hCatAdmin</c> member; 72 bytes on x64.
    /// </summary>
    /// <remarks>
    /// Offsets: cbStruct 0, dwCatalogVersion 4, pcwszCatalogFilePath 8, pcwszMemberTag 16,
    /// pcwszMemberFilePath 24, hMemberFile 32, pbCalculatedFileHash 40, cbCalculatedFileHash 48,
    /// pcCatalogContext 56, hCatAdmin 64. <c>hCatAdmin</c> is not optional for SHA-256 catalogs:
    /// measured on Windows 11 26200, verifying <c>PING.EXE</c> against its catalog with it returns 0
    /// and without it returns <c>TRUST_E_NOSIGNATURE</c>.
    /// </remarks>
    [StructLayout(LayoutKind.Sequential)]
    internal struct WinTrustCatalogInfo
    {
        public uint StructSize;
        public uint CatalogVersion;
        public nint CatalogFilePath;
        public nint MemberTag;
        public nint MemberFilePath;
        public nint MemberFile;
        public nint CalculatedFileHash;
        public uint CalculatedFileHashSize;
        public nint CatalogContext;
        public nint CatAdmin;
    }

    /// <summary>
    /// The leading fields of <c>CRYPT_PROVIDER_SGNR</c>, as far as the certificate chain pointer.
    /// </summary>
    /// <remarks>
    /// x64 layout: cbStruct 0, sftVerifyAsOf 4 (a FILETIME is two DWORDs, so 4-aligned),
    /// csCertChain 12, pasCertChain 16 (8-aligned, and 16 already is, so no padding). The remaining
    /// members are never read, and a sequential struct that stops here is read with
    /// <see cref="Marshal.PtrToStructure{T}(nint)"/> without touching them. Wintrust reports
    /// cbStruct 64 for the whole structure on Windows 11 26200.
    /// </remarks>
    [StructLayout(LayoutKind.Sequential)]
    internal struct CryptProviderSignerHead
    {
        public uint StructSize;
        public uint VerifyAsOfLow;
        public uint VerifyAsOfHigh;
        public uint CertChainCount;
        public nint CertChain;
    }

    /// <summary>
    /// The leading fields of <c>CRYPT_PROVIDER_CERT</c>: cbStruct 0, then 4 bytes of padding, then
    /// pCert (a <c>PCCERT_CONTEXT</c>) at 8. Wintrust reports cbStruct 88 for the whole structure.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct CryptProviderCertHead
    {
        public uint StructSize;
        public nint Certificate;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        nint securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        nint templateFile);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetFileInformationByHandle(
        SafeFileHandle file, out ByHandleFileInformation information);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetFilePointerEx(
        SafeFileHandle file, long distanceToMove, nint newFilePointer, uint moveMethod);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern nint OpenProcess(
        uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint processId);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseHandle(nint handle);

    /// <summary>Returns a Win32 error code directly; it does not set the last error.</summary>
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern int GetPackageFamilyName(
        nint process, ref uint length, [Out] char[]? packageFamilyName);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern int WinVerifyTrust(nint window, ref Guid action, ref WinTrustData data);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern nint WTHelperProvDataFromStateData(nint stateData);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern nint WTHelperGetProvSignerFromChain(
        nint providerData,
        uint signerIndex,
        [MarshalAs(UnmanagedType.Bool)] bool counterSigner,
        uint counterSignerIndex);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptCATAdminAcquireContext2(
        out nint catAdmin, nint subsystem, string? hashAlgorithm, nint strongHashPolicy, uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptCATAdminCalcHashFromFileHandle2(
        nint catAdmin, SafeFileHandle file, ref uint hashSize, [Out] byte[] hash, uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern nint CryptCATAdminEnumCatalogFromHash(
        nint catAdmin, byte[] hash, uint hashSize, uint flags, nint previousCatalog);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptCATCatalogInfoFromContext(nint catalog, nint catalogInfo, uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptCATAdminReleaseCatalogContext(nint catAdmin, nint catalog, uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptCATAdminReleaseContext(nint catAdmin, uint flags);

    // ---- Where a file is ---------------------------------------------------------------------

    internal const uint DriveRemovable = 2;
    internal const uint DriveFixed = 3;
    internal const uint DriveCdRom = 5;
    internal const uint DriveRamDisk = 6;

    [DllImport("kernel32.dll", EntryPoint = "GetDriveTypeW", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern uint GetDriveType(string rootPathName);

    [DllImport("kernel32.dll", EntryPoint = "GetLongPathNameW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern uint GetLongPathName(string shortPath, [Out] char[] longPath, uint bufferLength);

    // ---- Version resource --------------------------------------------------------------------

    /// <summary>
    /// FILE_VER_GET_NEUTRAL: the version resource of the file itself, not its MUI satellite. The
    /// satellite is a separate file the signature does not cover, and the reason Windows binaries
    /// report a different product name in every display language.
    /// </summary>
    internal const uint FileVerGetNeutral = 0x02;

    [DllImport("version.dll", EntryPoint = "GetFileVersionInfoSizeExW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern uint GetFileVersionInfoSizeEx(uint flags, string fileName, out uint handle);

    [DllImport("version.dll", EntryPoint = "GetFileVersionInfoExW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetFileVersionInfoEx(uint flags, string fileName, uint handle, uint length, [Out] byte[] data);

    [DllImport("version.dll", EntryPoint = "VerQueryValueW", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool VerQueryValue(byte[] block, string subBlock, out nint buffer, out uint length);

    // ---- Package origin ----------------------------------------------------------------------

    /// <summary>PackageOrigin_Unsigned: registered from loose files with no signature.</summary>
    internal const int PackageOriginUnsigned = 1;

    /// <summary>PackageOrigin_DeveloperUnsigned: registered in Developer Mode from an unsigned layout.</summary>
    internal const int PackageOriginDeveloperUnsigned = 4;

    /// <summary>Returns a Win32 error code directly.</summary>
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern int GetPackageFullName(nint process, ref uint length, [Out] char[]? packageFullName);

    /// <summary>Returns a Win32 error code directly.</summary>
    /// <remarks>
    /// From the app-model API set, not kernel32: kernel32 does not export it (checked on Windows 11
    /// 26200), and importing it from there threw on the first packaged process the engine resolved.
    /// </remarks>
    [DllImport("api-ms-win-appmodel-runtime-l1-1-1.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern int GetStagedPackageOrigin(string packageFullName, out int origin);
}
