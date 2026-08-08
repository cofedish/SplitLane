import Foundation
import NetworkExtension
import Security
import SplitLaneCore

/// Resolves the SOCKS5 password inside the provider.
///
/// The password never travels in `providerConfiguration` — that is a plist in system NE
/// preferences, root-readable and visible to `scutil --nc` (F-5). It travels as
/// `NEVPNProtocol.passwordReference`, a persistent reference to a `kSecClassGenericPassword`
/// Keychain item, which is the channel Apple provides for exactly this purpose.
///
/// The resolved password is held only for the duration of one handshake. It is not cached, not
/// stored on the provider, and never logged in any form.
enum CredentialProvider {

    /// Builds a credential for a proxy configuration, or nil when none is needed.
    ///
    /// Returns nil when the configuration declares no credential. Returns nil *and logs* when a
    /// credential is declared but the password cannot be resolved — the handshake then offers only
    /// NO AUTH, the server rejects it, and the connection fails closed with a diagnosable error.
    /// Fabricating an empty password instead would produce a misleading "authentication failed".
    static func credential(for proxy: SplitLaneCore.ProxyConfiguration) async -> SOCKS5Credential? {
        guard let reference = proxy.credential else { return nil }

        guard let password = resolvePassword(reference: reference) else {
            SplitLaneLog.security.error(
                """
                Proxy authentication is configured for user \
                \(SplitLaneLog.redacted(reference.username), privacy: .public) \
                but the Keychain item could not be resolved
                """
            )
            return nil
        }

        return SOCKS5Credential(username: reference.username, password: password)
    }

    /// Looks up a password from a base64-encoded Keychain persistent reference.
    private static func resolvePassword(reference: CredentialReference) -> String? {
        guard
            let encoded = reference.persistentReference,
            let referenceData = Data(base64Encoded: encoded)
        else { return nil }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecValuePersistentRef as String: referenceData,
            kSecReturnData as String: true,
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess, let data = result as? Data else {
            // The status code is safe to log: it says why the lookup failed, not what was stored.
            SplitLaneLog.security.error(
                "Keychain lookup failed with status \(status, privacy: .public)"
            )
            return nil
        }
        return String(data: data, encoding: .utf8)
    }
}
