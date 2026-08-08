import Foundation
import Security
import SplitLaneCore

/// Stores the SOCKS5 password in the Keychain and hands out a persistent reference.
///
/// The password never enters `providerConfiguration` — that is a plist in system NE preferences,
/// root-readable and visible to `scutil --nc`. What travels instead is a persistent reference,
/// which the provider resolves through `NEVPNProtocol.passwordReference`. See F-5.
enum KeychainService {

    static let service = "dev.cofe.splitlane.proxy-credentials"

    enum KeychainError: Error, LocalizedError {
        case unexpectedStatus(OSStatus)
        case missingPersistentReference

        var errorDescription: String? {
            switch self {
            case .unexpectedStatus(let status):
                "Keychain operation failed with status \(status)"
            case .missingPersistentReference:
                "The Keychain did not return a reference for the saved password"
            }
        }
    }

    /// Saves (or replaces) the password for an account and returns a persistent reference.
    ///
    /// Delete-then-add rather than `SecItemUpdate`: updating cannot return a persistent reference
    /// in the same call, and the reference is the whole reason this function exists.
    @discardableResult
    static func savePassword(_ password: String, account: String) throws -> Data {
        try? deletePassword(account: account)

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: Data(password.utf8),
            // The provider runs as root at boot, before any user unlocks the login keychain, so
            // the item must be readable without user presence and must not be device-scoped in a
            // way that blocks a background daemon.
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
            kSecReturnPersistentRef as String: true,
        ]

        var result: CFTypeRef?
        let status = SecItemAdd(query as CFDictionary, &result)
        guard status == errSecSuccess else { throw KeychainError.unexpectedStatus(status) }
        guard let reference = result as? Data else { throw KeychainError.missingPersistentReference }
        return reference
    }

    /// Reads back a password. Used by the UI to prefill the field, never for logging.
    static func password(account: String) throws -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw KeychainError.unexpectedStatus(status) }
        guard let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func deletePassword(account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(status)
        }
    }

    /// Builds the reference that goes into the configuration. Carries no secret material.
    static func credentialReference(username: String, password: String) throws -> CredentialReference {
        let reference = try savePassword(password, account: username)
        return CredentialReference(
            username: username,
            persistentReference: reference.base64EncodedString()
        )
    }
}
