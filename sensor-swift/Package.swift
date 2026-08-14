// swift-tools-version: 6.0

import PackageDescription

let package = Package(
  name: "MacSentinelSensor",
  platforms: [.macOS(.v13)],
  products: [
    .library(name: "MacSentinelSensor", targets: ["MacSentinelSensor"]),
    .executable(name: "macsentinel-sensor", targets: ["MacSentinelSensorCLI"]),
  ],
  targets: [
    .target(name: "MacSentinelSensor"),
    .executableTarget(
      name: "MacSentinelSensorCLI",
      dependencies: ["MacSentinelSensor"]
    ),
    .testTarget(
      name: "MacSentinelSensorTests",
      dependencies: ["MacSentinelSensor"]
    ),
  ]
)
