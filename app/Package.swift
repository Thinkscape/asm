// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "AsmApp",
    platforms: [.macOS(.v14)],
    targets: [
        .binaryTarget(name: "AsmCoreFFI", path: "AsmCoreFFI.xcframework"),
        .target(
            name: "AsmCore",
            dependencies: ["AsmCoreFFI"],
            swiftSettings: [.swiftLanguageMode(.v5)],
            // From `just core-native-libs` (cargo --print native-static-libs).
            linkerSettings: [
                .linkedFramework("Security"),
                .linkedFramework("CoreFoundation"),
                .linkedLibrary("iconv"),
                .linkedLibrary("System"),
                .linkedLibrary("c"),
                .linkedLibrary("m"),
            ]
        ),
        .executableTarget(name: "AsmApp", dependencies: ["AsmCore"]),
    ]
)
