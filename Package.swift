// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "NeoneWebAuthnCore",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .library(name: "NeoneWebAuthnCore", targets: ["NeoneWebAuthnCore"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .target(
            name: "NeoneWebAuthnCore",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "NeoneWebAuthnCoreTests",
            dependencies: [
                .target(name: "NeoneWebAuthnCore"),
            ],
            swiftSettings: swiftSettings
        ),
    ]
)

var swiftSettings: [SwiftSetting] { [
    .enableUpcomingFeature("ExistentialAny"),
] }
