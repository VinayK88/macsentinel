import Foundation
import XCTest

@testable import MacSentinelSensor

private func sampleEvent(
  host: String = "mac-personal-name",
  user: String = "vinay@example.test",
  session: String = "session-private",
  target: String = "/Users/vinay/Documents/private.txt"
) -> RawMacOSEvent {
  RawMacOSEvent(
    eventID: "evt-1",
    timestamp: "2026-01-15 08:01:03+00:00",
    hostID: host,
    userID: user,
    sessionID: session,
    step: 1,
    parentProcess: "/bin/zsh",
    process: "/usr/bin/curl",
    eventType: "network_connect",
    target: target,
    relation: "connects",
    signed: true,
    notarized: true,
    gatekeeperBypass: false,
    xprotectDetection: false,
    privilegeEscalation: false,
    persistenceWrite: false,
    sensitiveAccess: true,
    networkBeacon: true,
    fileWriteCount: 0,
    bytesOut: 128,
    commandRisk: 0.42,
    scenario: "credential_access",
    mitreTechnique: "T1555.001",
    label: 1,
    dataSource: "test"
  )
}

final class SensorTests: XCTestCase {
  func testCSVParserPreservesQuotedCommasAndEscapedQuotes() {
    XCTAssertEqual(
      parseCSVLine("alpha,\"bravo,charlie\",\"say \"\"hello\"\"\""),
      [
        "alpha", "bravo,charlie", "say \"hello\"",
      ])
  }

  func testPrivacyTokensAreDeterministicSaltedAndOmitRawValues() throws {
    let event = sampleEvent()
    let first = try PrivacyFilter(salt: "0123456789abcdef").normalize(event)
    let repeated = try PrivacyFilter(salt: "0123456789abcdef").normalize(event)
    let changedSalt = try PrivacyFilter(salt: "fedcba9876543210").normalize(event)

    XCTAssertEqual(first, repeated)
    XCTAssertNotEqual(first.hostToken, changedSalt.hostToken)
    XCTAssertEqual(first.process, "curl")
    XCTAssertEqual(first.parentProcess, "zsh")
    let rendered = String(decoding: try JSONEncoder().encode(first), as: UTF8.self)
    XCTAssertFalse(rendered.contains(event.eventID))
    XCTAssertFalse(rendered.contains(event.hostID))
    XCTAssertFalse(rendered.contains(event.userID))
    XCTAssertFalse(rendered.contains(event.sessionID))
    XCTAssertFalse(rendered.contains(event.target))
  }

  func testPrivacySaltRejectsUnsafeShortValues() {
    XCTAssertThrowsError(try PrivacyFilter(salt: "short")) { error in
      XCTAssertEqual(
        error as? SensorError,
        .invalidArgument("privacy salt must contain at least 16 UTF-8 bytes")
      )
    }
  }

  func testDropNewestBufferIsBoundedAndReportsPressure() throws {
    var buffer = try BoundedEventBuffer<Int>(capacity: 2, overflowPolicy: .dropNewest)
    XCTAssertTrue(buffer.append(1))
    XCTAssertTrue(buffer.append(2))
    XCTAssertFalse(buffer.append(3))
    XCTAssertEqual(buffer.droppedCount, 1)
    XCTAssertEqual(buffer.highWatermark, 2)
    XCTAssertEqual(buffer.drain(), [1, 2])
  }

  func testDropOldestBufferRetainsNewestEvidence() throws {
    var buffer = try BoundedEventBuffer<Int>(capacity: 2, overflowPolicy: .dropOldest)
    XCTAssertTrue(buffer.append(1))
    XCTAssertTrue(buffer.append(2))
    XCTAssertTrue(buffer.append(3))
    XCTAssertEqual(buffer.droppedCount, 1)
    XCTAssertEqual(buffer.drain(), [2, 3])
  }

  func testAuthorizedEndpointSecurityMetadataUsesSharedSourceBoundary() throws {
    let source = EndpointSecurityMetadataSource(metadata: [
      AuthorizedEndpointSecurityMetadata(event: sampleEvent())
    ])
    var observed: [RawMacOSEvent] = []
    try source.forEachEvent { observed.append($0) }
    XCTAssertEqual(source.sourceName, "authorized-endpoint-security-metadata")
    XCTAssertEqual(observed, [sampleEvent()])
  }

  func testLiveCollectionFailsClosedWithoutExplicitAuthorization() {
    XCTAssertThrowsError(try LiveEndpointSecuritySource.requireAuthorization()) { error in
      XCTAssertEqual(error as? SensorError, .endpointSecurityEntitlementRequired)
    }
  }

  func testFullFixtureReplaysWithoutDropsOrPrivacyLeakage() throws {
    let testFile = URL(fileURLWithPath: #filePath)
    let packageRoot =
      testFile
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
    let fixture =
      packageRoot
      .deletingLastPathComponent()
      .appendingPathComponent("data/synthetic_macos_events.csv")
    let pipeline = try SensorPipeline(
      privacyFilter: PrivacyFilter(salt: "macsentinel-test-salt-v1"),
      queueCapacity: 256,
      batchSize: 64
    )
    var sinkCount = 0
    let report = try pipeline.run(source: ReplayCSVEventSource(inputURL: fixture)) {
      sinkCount += $0.count
    }

    XCTAssertEqual(report.eventsRead, 2_520)
    XCTAssertEqual(report.eventsEmitted, 2_520)
    XCTAssertEqual(sinkCount, 2_520)
    XCTAssertEqual(report.eventsDropped, 0)
    XCTAssertEqual(report.queueHighWatermark, 64)
    XCTAssertTrue(report.privacyChecksPassed)
    XCTAssertGreaterThan(report.eventsPerSecond, 0)
    XCTAssertGreaterThan(report.p95NormalizationMicros, 0)
  }
}
