// swift-tools-version:5.1
import PackageDescription

let package = Package(
    name: "OneTimePassword",
    platforms: [
        .iOS(.v8),
        .watchOS(.v2),
    ],
    products: [
        .library(
            name: "OneTimePassword",
            type: .dynamic,
            targets: ["OneTimePassword"]
        )
    ],
    dependencies: [
        .package(
            url: "https://github.com/2FAuth/Base32",
            .revision("2901af815f77d869af0631a319e2ed7efde79cee")
        )
    ],
    targets: [
        .target(
            name: "OneTimePassword",
            dependencies: ["Base32"],
            path: "Sources"
        ),
        .testTarget(
            name: "OneTimePasswordTests",
            dependencies: ["OneTimePassword"],
            path: "Tests",
            exclude: ["KeychainTests.swift", "App"]
        )
    ]
)
