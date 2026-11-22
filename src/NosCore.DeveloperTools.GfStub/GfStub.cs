using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace NosCore.DeveloperTools.GfStub;

/// <summary>
/// Drop-in replacement for the NosTale client's <c>gf_wrapper.dll</c>. The
/// real wrapper chain (<c>gf_wrapper</c> → <c>psw_tnt</c> → <c>gameforge_api</c>
/// → <c>gameforge_client_api</c>) talks JSON-RPC over
/// <c>\\.\pipe\GameforgeClientJSONRPC</c> to a running Gameforge launcher to
/// fetch the auth code, and fails with "gf init failed" without one.
///
/// This stub bypasses the chain entirely: <c>Steam_GetAuthSessionTicket</c>
/// hands back the <c>_NC_AUTH_CODE</c> GUID as its ASCII string form (with
/// dashes). The client pipes that straight into the NoS0577 AuthToken field
/// verbatim, and NosCore's AuthHub resolves it via <c>Guid.TryParse</c> — so
/// sending the 16 raw bytes instead would break server-side parsing. The
/// <c>InstallationId</c> registry key is seeded so NoS0577 doesn't reject a
/// NONE_CII value, reusing the official Gameforge client's id when one exists.
/// </summary>
internal static unsafe class GfStub
{
    [ModuleInitializer]
    internal static void OnLoad()
    {
        try { EnsureInstallationId(); } catch { }
        try { LoadAuthCodeFromEnv(); } catch { }
    }

    [UnmanagedCallersOnly(EntryPoint = "Steam_Init", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static int Steam_Init() => 1;

    [UnmanagedCallersOnly(EntryPoint = "Steam_IsLoggedIn", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static int Steam_IsLoggedIn() => 1;

    [UnmanagedCallersOnly(EntryPoint = "Steam_IsOverlayEnabled", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static int Steam_IsOverlayEnabled() => 0;

    [UnmanagedCallersOnly(EntryPoint = "Steam_OnFrameTick", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static void Steam_OnFrameTick() { }

    [UnmanagedCallersOnly(EntryPoint = "Steam_SetOverlayActivateCallback", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static void Steam_SetOverlayActivateCallback(IntPtr callback) { }

    [UnmanagedCallersOnly(EntryPoint = "Steam_OpenOverlayToWebPage", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static void Steam_OpenOverlayToWebPage(IntPtr url) { }

    [UnmanagedCallersOnly(EntryPoint = "Steam_CancelAuthSessionTicket", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static void Steam_CancelAuthSessionTicket(uint ticketHandle) { }

    [UnmanagedCallersOnly(EntryPoint = "Steam_GetAuthSessionTicket", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static uint Steam_GetAuthSessionTicket(IntPtr buffer, int bufferSize, IntPtr pTicketSize)
    {
        if (_authCodeBytes is null || _authCodeBytes.Length == 0 || buffer == IntPtr.Zero)
        {
            if (pTicketSize != IntPtr.Zero) Marshal.WriteInt32(pTicketSize, 0);
            return 0;
        }
        var len = Math.Min(_authCodeBytes.Length, bufferSize);
        Marshal.Copy(_authCodeBytes, 0, buffer, len);
        if (pTicketSize != IntPtr.Zero) Marshal.WriteInt32(pTicketSize, len);
        return 1;
    }

    [UnmanagedCallersOnly(EntryPoint = "Steam_GetPersonaName", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static IntPtr Steam_GetPersonaName() => PinAscii("");

    [UnmanagedCallersOnly(EntryPoint = "Steam_GetSteamLanguage", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static IntPtr Steam_GetSteamLanguage() => PinAscii("english");

    [UnmanagedCallersOnly(EntryPoint = "Steam_GetConnectedBetaBranch", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static IntPtr Steam_GetConnectedBetaBranch() => PinAscii("live");

    private static byte[]? _authCodeBytes;

    private static readonly Dictionary<string, IntPtr> _asciiCache = new();

    private static IntPtr PinAscii(string value)
    {
        lock (_asciiCache)
        {
            if (_asciiCache.TryGetValue(value, out var existing)) return existing;
            var bytes = Encoding.ASCII.GetBytes(value + "\0");
            var p = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, p, bytes.Length);
            _asciiCache[value] = p;
            return p;
        }
    }

    private static void LoadAuthCodeFromEnv()
    {
        var env = Environment.GetEnvironmentVariable("_NC_AUTH_CODE");
        if (string.IsNullOrEmpty(env)) return;
        if (Guid.TryParse(env, out var g))
        {
            // Client pipes whatever Steam_GetAuthSessionTicket returns straight
            // into the NoS0577 AuthToken field verbatim; NosCore's AuthHub then
            // tries Guid.TryParse on that string. So ship the full GUID text
            // (with dashes) as ASCII — NOT the 16 raw bytes.
            _authCodeBytes = Encoding.ASCII.GetBytes(g.ToString());
        }
    }

    private const string InstallKeyPath = @"SOFTWARE\WOW6432Node\Gameforge4d\GameforgeClient\MainApp";
    private const string UserInstallKeyPath = @"SOFTWARE\Gameforge4d\GameforgeClient\MainApp";
    private const string InstallValueName = "InstallationId";

    private static void EnsureInstallationId()
    {
        if (RegReadString(HKEY_LOCAL_MACHINE, InstallKeyPath, InstallValueName) is not null) return;
        // An unelevated write to the machine key lands in the user's VirtualStore, and the official
        // Gameforge client (also 32-bit) then reads it ahead of its own per-user id. A freshly minted
        // id would silently re-register that installation, so reuse the official one when it exists.
        if (RegReadString(HKEY_CURRENT_USER, UserInstallKeyPath, InstallValueName) is { } official)
        {
            RegWriteString(HKEY_LOCAL_MACHINE, InstallKeyPath, InstallValueName, official);
            return;
        }
        RegWriteString(HKEY_LOCAL_MACHINE, InstallKeyPath, InstallValueName, Guid.NewGuid().ToString().ToUpperInvariant());
    }

    private const uint KEY_READ = 0x20019;
    private const uint KEY_WRITE = 0x20006;
    private const uint REG_SZ = 1;
    private static readonly IntPtr HKEY_CURRENT_USER = (IntPtr)unchecked((int)0x80000001);
    private static readonly IntPtr HKEY_LOCAL_MACHINE = (IntPtr)unchecked((int)0x80000002);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegOpenKeyExW(IntPtr hKey, string subKey, int options, uint samDesired, out IntPtr phkResult);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegCreateKeyExW(IntPtr hKey, string subKey, int reserved, IntPtr classType, int options,
        uint samDesired, IntPtr securityAttributes, out IntPtr phkResult, out int lpdwDisposition);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegQueryValueExW(IntPtr hKey, string lpValueName, IntPtr lpReserved, out uint lpType,
        byte[]? lpData, ref uint lpcbData);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegSetValueExW(IntPtr hKey, string lpValueName, int reserved, uint dwType,
        byte[] lpData, uint cbData);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int RegCloseKey(IntPtr hKey);

    private static string? RegReadString(IntPtr hive, string keyPath, string valueName)
    {
        if (RegOpenKeyExW(hive, keyPath, 0, KEY_READ, out var hKey) != 0) return null;
        try
        {
            uint cb = 0;
            if (RegQueryValueExW(hKey, valueName, IntPtr.Zero, out _, null, ref cb) != 0 || cb == 0) return null;
            var buf = new byte[cb];
            if (RegQueryValueExW(hKey, valueName, IntPtr.Zero, out _, buf, ref cb) != 0) return null;
            var s = Encoding.Unicode.GetString(buf, 0, (int)cb).TrimEnd('\0');
            return s.Length == 0 ? null : s;
        }
        finally
        {
            RegCloseKey(hKey);
        }
    }

    private static void RegWriteString(IntPtr hive, string keyPath, string valueName, string value)
    {
        if (RegCreateKeyExW(hive, keyPath, 0, IntPtr.Zero, 0, KEY_WRITE, IntPtr.Zero, out var hKey, out _) != 0) return;
        try
        {
            var bytes = Encoding.Unicode.GetBytes(value + "\0");
            RegSetValueExW(hKey, valueName, 0, REG_SZ, bytes, (uint)bytes.Length);
        }
        finally
        {
            RegCloseKey(hKey);
        }
    }
}
