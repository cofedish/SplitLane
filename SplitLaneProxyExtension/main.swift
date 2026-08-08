import Foundation
import NetworkExtension
import SplitLaneCore

// Entry point for the SplitLane proxy system extension.
//
// A NetworkExtension provider packaged as a *system* extension is a plain executable, not an
// app extension: it starts here and hands control to the NetworkExtension machinery, which
// instantiates the provider class named by `NEProviderClasses` in Info.plist and then owns its
// lifecycle. `startSystemExtensionMode()` does not return.
//
// This file is `main.swift` deliberately — top-level code is only permitted there, and a
// system extension needs a real entry point rather than an `@main` type.

SplitLaneLog.extensionLifecycle.notice("SplitLaneProxyExtension entering system extension mode")

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}

// startSystemExtensionMode() blocks. Reaching this line means the NetworkExtension runtime
// declined to take over, which is fatal and worth recording rather than exiting silently.
SplitLaneLog.extensionLifecycle.fault("startSystemExtensionMode returned unexpectedly")
dispatchMain()
