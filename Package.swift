// swift-tools-version:5.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "ipspatcherFuzzer",
    dependencies: [
        .package(url: "../ipspatcher", from: "0.0.3"),
        .package(url: "../FuzzerInterface", from: "0.0.1"),
    ],
    targets: [
        .target(
            name: "ipspatcherFuzzer",
            dependencies: ["ipspatcher"]),
        .testTarget(
            name: "ipspatcherFuzzerTests",
            dependencies: ["ipspatcherFuzzer"]),
    ]
)
