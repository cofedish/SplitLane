import AppKit
import Foundation
import Security
import SplitLaneCore

/// Extracts the identity SplitLane routes on from an application bundle.
///
/// The routing key is the **code signing identifier**, read from `SecStaticCode`, because that is
/// what `NEFlowMetaData` hands the provider at flow time. The bundle identifier is captured
/// separately rather than assumed equal: `NEFlowMetaData.h` only promises they are "almost always"
/// the same, and a rule built on the wrong one silently never matches. See ADR 0002.
enum ApplicationInspector {

    enum InspectionError: Error, LocalizedError {
        case notAnApplication(URL)
        case unsignedOrUnreadable(URL, OSStatus)
        case missingSigningIdentifier(URL)

        var errorDescription: String? {
            switch self {
            case .notAnApplication(let url):
                "\(url.lastPathComponent) is not an application bundle"
            case .unsignedOrUnreadable(let url, let status):
                "Could not read the code signature of \(url.lastPathComponent) (status \(status))"
            case .missingSigningIdentifier(let url):
                "\(url.lastPathComponent) has no code signing identifier, so it cannot be routed"
            }
        }
    }

    /// Inspects an application bundle.
    static func inspect(bundleURL: URL) throws -> AppIdentity {
        guard bundleURL.pathExtension == "app", let bundle = Bundle(url: bundleURL) else {
            throw InspectionError.notAnApplication(bundleURL)
        }

        let signing = try signingInformation(for: bundleURL)

        guard let signingIdentifier = signing.identifier, !signingIdentifier.isEmpty else {
            // Without an identifier there is nothing to match a flow against. Refusing here is
            // better than creating a rule that can never fire.
            throw InspectionError.missingSigningIdentifier(bundleURL)
        }

        let displayName = (bundle.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String)
            ?? (bundle.object(forInfoDictionaryKey: "CFBundleName") as? String)
            ?? bundleURL.deletingPathExtension().lastPathComponent

        return AppIdentity(
            signingIdentifier: signingIdentifier,
            teamIdentifier: signing.teamIdentifier,
            bundleIdentifier: bundle.bundleIdentifier,
            displayName: displayName,
            bundlePath: bundleURL.path
        )
    }

    /// Reads the signing identifier and team identifier from a bundle's static code signature.
    private static func signingInformation(for url: URL) throws
        -> (identifier: String?, teamIdentifier: String?)
    {
        var staticCode: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode)
        guard createStatus == errSecSuccess, let staticCode else {
            throw InspectionError.unsignedOrUnreadable(url, createStatus)
        }

        // kSecCSSigningInformation is what carries the identifier and team identifier.
        var information: CFDictionary?
        let infoStatus = SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &information
        )
        guard infoStatus == errSecSuccess, let dictionary = information as? [String: Any] else {
            throw InspectionError.unsignedOrUnreadable(url, infoStatus)
        }

        return (
            identifier: dictionary[kSecCodeInfoIdentifier as String] as? String,
            teamIdentifier: dictionary[kSecCodeInfoTeamIdentifier as String] as? String
        )
    }

    /// The application's icon, for display only.
    static func icon(forBundlePath path: String) -> NSImage {
        NSWorkspace.shared.icon(forFile: path)
    }

    /// Presents the standard macOS application picker.
    ///
    /// `/Applications` is the starting directory rather than a restriction — apps in
    /// `~/Applications` or elsewhere are perfectly valid targets.
    @MainActor
    static func presentPicker() -> [URL] {
        let panel = NSOpenPanel()
        panel.title = "Add Application"
        panel.message = "Choose applications to route through the proxy lane"
        panel.prompt = "Add"
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowedContentTypes = [.application]
        panel.directoryURL = URL(fileURLWithPath: "/Applications")

        return panel.runModal() == .OK ? panel.urls : []
    }
}
