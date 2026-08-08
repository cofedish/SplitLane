import Foundation
import SplitLaneCore
import SystemExtensions

/// Installs and activates the SplitLane proxy system extension.
///
/// Uses `OSSystemExtensionRequest` exclusively. There is no privileged helper and no shell script:
/// approval is a user decision that macOS is entitled to ask for, and routing around it would be
/// both fragile and wrong.
@MainActor
@Observable
final class ExtensionManager: NSObject {

    /// Where installation currently stands.
    enum State: Equatable {
        case unknown
        case notInstalled
        case installing
        /// macOS is waiting for the user to approve the extension in System Settings.
        case awaitingApproval
        /// Replacing an already-installed copy; usually needs a reboot to finish.
        case awaitingReboot
        case installed
        case failed(String)

        var isUsable: Bool { self == .installed }

        var summary: String {
            switch self {
            case .unknown: "Checking…"
            case .notInstalled: "Not installed"
            case .installing: "Installing…"
            case .awaitingApproval: "Waiting for approval in System Settings"
            case .awaitingReboot: "Restart required to finish updating"
            case .installed: "Installed"
            case .failed(let reason): "Failed: \(reason)"
            }
        }
    }

    static let extensionIdentifier = "dev.cofe.splitlane.proxyextension"

    private(set) var state: State = .unknown

    /// Serialises activation requests.
    ///
    /// Two in-flight `OSSystemExtensionRequest`s for the same identifier produce
    /// `OSSystemExtensionErrorRequestSuperseded`, which looks like a real failure and is not.
    private var activationInProgress = false

    /// Requests activation.
    func activate() {
        guard !activationInProgress else {
            SplitLaneLog.extensionLifecycle.notice("Activation already in progress; ignoring")
            return
        }
        activationInProgress = true
        state = .installing

        SplitLaneLog.extensionLifecycle.notice(
            "Requesting activation of \(Self.extensionIdentifier, privacy: .public)"
        )

        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: Self.extensionIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    /// Requests deactivation. Also prompts the user for approval.
    func deactivate() {
        SplitLaneLog.extensionLifecycle.notice("Requesting deactivation")
        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: Self.extensionIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }
}

extension ExtensionManager: OSSystemExtensionRequestDelegate {

    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension replacement: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        SplitLaneLog.extensionLifecycle.notice(
            """
            Replacing extension \(existing.bundleShortVersion, privacy: .public) \
            (\(existing.bundleVersion, privacy: .public)) with \
            \(replacement.bundleShortVersion, privacy: .public) \
            (\(replacement.bundleVersion, privacy: .public))
            """
        )
        // Always replace. During development the version often has not changed, and refusing the
        // replacement is the single most common reason edited code appears to have no effect.
        return .replace
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Task { @MainActor in
            SplitLaneLog.extensionLifecycle.notice("Extension needs user approval")
            state = .awaitingApproval
        }
    }

    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        Task { @MainActor in
            activationInProgress = false
            switch result {
            case .completed:
                SplitLaneLog.extensionLifecycle.notice("Extension activation completed")
                state = .installed
            case .willCompleteAfterReboot:
                SplitLaneLog.extensionLifecycle.notice("Extension activation needs a reboot")
                state = .awaitingReboot
            @unknown default:
                state = .failed("Unknown activation result")
            }
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        Task { @MainActor in
            activationInProgress = false
            let nsError = error as NSError
            SplitLaneLog.extensionLifecycle.error(
                "Extension request failed: \(nsError.domain, privacy: .public) \(nsError.code, privacy: .public)"
            )
            state = .failed(Self.explain(nsError))
        }
    }

    /// Turns an OSSystemExtension error into something a developer can act on.
    ///
    /// The raw messages are unhelpfully generic, and the causes are nearly always one of a small
    /// set of setup problems rather than a genuine runtime fault.
    private static func explain(_ error: NSError) -> String {
        guard error.domain == OSSystemExtensionErrorDomain,
              let code = OSSystemExtensionError.Code(rawValue: error.code)
        else {
            return error.localizedDescription
        }

        switch code {
        case .validationFailed:
            return "Signing or entitlements are invalid. The app must be in /Applications and both "
                 + "app and extension must be signed by the same team with the NetworkExtension entitlement."
        case .requestSuperseded:
            return "A newer activation request replaced this one."
        case .authorizationRequired:
            return "Approval is required in System Settings → General → Login Items & Extensions."
        case .extensionNotFound:
            return "The extension was not found inside the app bundle."
        case .unsupportedParentBundleLocation:
            return "System extensions can only be activated from an app in /Applications."
        case .codeSignatureInvalid:
            return "The code signature is invalid."
        case .forbiddenBySystemPolicy:
            return "Blocked by system policy. On Apple Silicon a locally-built extension usually "
                 + "needs `systemextensionsctl developer on`."
        default:
            return error.localizedDescription
        }
    }
}
