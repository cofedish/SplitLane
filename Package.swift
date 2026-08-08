// swift-tools-version: 6.0
import PackageDescription

// SplitLaneCore is a SwiftPM library so that the rule engine, the SOCKS5 implementation,
// configuration coding and IPC messages build and test with the Command Line Tools alone —
// no Xcode, no signing, no approved system extension. See docs/adr/0007-*.md.
//
// The Xcode project (generated from project.yml) consumes this package locally, so the app
// and the extension share exactly one copy of the source.

let package = Package(
    name: "SplitLaneCore",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "SplitLaneCore", targets: ["SplitLaneCore"])
    ],
    targets: [
        .target(
            name: "SplitLaneCore",
            path: "Sources/SplitLaneCore",
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "SplitLaneCoreTests",
            dependencies: ["SplitLaneCore"],
            path: "Tests/SplitLaneCoreTests",
            swiftSettings: [.swiftLanguageMode(.v6)]
        )
    ]
)
